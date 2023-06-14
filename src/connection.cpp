#include "connection.hpp"

#include <arpa/inet.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <netinet/ip.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <uvw/async.h>
#include <uvw/timer.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>

#include "client.hpp"
#include "endpoint.hpp"
#include "handler.hpp"
#include "server.hpp"
#include "stream.hpp"

extern ngtcp2_tstamp OMG_DEBUG[8];

namespace oxen::quic
{
    using namespace std::literals;

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return static_cast<Connection*>(conn_ref->user_data)->conn.get();
        }

        void log_printer(void* user_data, const char* fmt, ...)
        {
            std::array<char, 2048> buf{};
            va_list ap;
            va_start(ap, fmt);
            if (vsnprintf(buf.data(), buf.size(), fmt, ap) >= 0)
                log::debug(log_cat, "{}", buf.data());
            va_end(ap);
        }
    }

    int hook_func(
            gnutls_session_t session, unsigned int htype, unsigned when, unsigned int incoming, const gnutls_datum_t* msg)
    {
        (void)session;
        (void)htype;
        (void)when;
        (void)incoming;
        (void)msg;
        /* we could save session data here */

        return 0;
    }

    int recv_stream_data(
            ngtcp2_conn* conn,
            uint32_t flags,
            int64_t stream_id,
            uint64_t offset,
            const uint8_t* data,
            size_t datalen,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_receive(
                stream_id, {reinterpret_cast<const std::byte*>(data), datalen}, flags & NGTCP2_STREAM_DATA_FLAG_FIN);
    }

    int64_t DEBUG_acks = 0;
    int64_t DEBUG_ack_data = 0;
    int acked_stream_data_offset(
            ngtcp2_conn* conn_,
            int64_t stream_id,
            uint64_t offset,
            uint64_t datalen,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Ack [{},{}]", offset, offset + datalen);
        DEBUG_acks++;
        DEBUG_ack_data += datalen;
        return static_cast<Connection*>(user_data)->stream_ack(stream_id, datalen);
    }

    int on_stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return static_cast<Connection*>(user_data)->stream_opened(stream_id);
    }

    int on_stream_close(
            ngtcp2_conn* conn,
            uint32_t flags,
            int64_t stream_id,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    int on_stream_reset(
            ngtcp2_conn* conn,
            int64_t stream_id,
            uint64_t final_size,
            uint64_t app_error_code,
            void* user_data,
            void* stream_user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        static_cast<Connection*>(user_data)->stream_closed(stream_id, app_error_code);
        return 0;
    }

    void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx)
    {
        (void)rand_ctx;
        (void)gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
    }

    int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        (void)conn;
        (void)user_data;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        cid->datalen = cidlen;

        if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0)
            return NGTCP2_ERR_CALLBACK_FAILURE;

        return 0;
    }

    int recv_rx_key(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data)
    {
        // fix this
        return 0;
    }

    int recv_tx_key(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data)
    {
        // same
        return 0;
    }

    int extend_max_local_streams_bidi(ngtcp2_conn* _conn, uint64_t max_streams, void* user_data)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        auto& conn = *static_cast<Connection*>(user_data);
        assert(_conn == conn);

        if (auto remaining = ngtcp2_conn_get_streams_bidi_left(conn); remaining > 0)
            conn.check_pending_streams(remaining);

        return 0;
    }

    Server* Connection::server()
    {
        return dynamic_cast<Server*>(&endpoint);
    }
    const Server* Connection::server() const
    {
        return dynamic_cast<const Server*>(&endpoint);
    }

    Client* Connection::client()
    {
        return dynamic_cast<Client*>(&endpoint);
    }
    const Client* Connection::client() const
    {
        return dynamic_cast<const Client*>(&endpoint);
    }

    void Connection::io_ready()
    {
        io_trigger->send();
    }

    // note: this does not need to return anything, it is never called except in on_stream_available
    // First, we check the list of pending streams on deck to see if they're ready for broadcast. If
    // so, we move them to the streams map, where they will get picked up by flush_streams and dump
    // their buffers. If none are ready, we keep chugging along and make another stream as usual. Though
    // if none of the pending streams are ready, the new stream really shouldn't be ready, but here we are
    void Connection::check_pending_streams(int available, stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        int popped = 0;

        while (!pending_streams.empty() && popped < available)
        {
            auto& str = pending_streams.front();

            if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &str->stream_id, str.get()); rv == 0)
            {
                log::debug(log_cat, "Stream [ID:{}] ready for broadcast, moving out of pending streams", str->stream_id);
                str->set_ready();
                popped += 1;
                streams[str->stream_id] = std::move(str);
                pending_streams.pop_front();
            }
            else
                return;
        }
    }

    std::shared_ptr<Stream> Connection::get_new_stream(stream_data_callback_t data_cb, stream_close_callback_t close_cb)
    {
        auto stream = std::make_shared<Stream>(*this, std::move(data_cb), std::move(close_cb));

        if (int rv = ngtcp2_conn_open_bidi_stream(conn.get(), &stream->stream_id, stream.get()); rv != 0)
        {
            log::warning(log_cat, "Stream not ready [Code: {}]; adding to pending streams list", ngtcp2_strerror(rv));
            stream->set_not_ready();
            pending_streams.push_back(std::move(stream));
            return pending_streams.back();
        }
        else
        {
            log::debug(log_cat, "Stream {} successfully created; ready to broadcast", stream->stream_id);
            stream->set_ready();
            auto& strm = streams[stream->stream_id];
            strm = std::move(stream);
            return strm;
        }
    }

    void Connection::on_io_ready()
    {
        // log::warning(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto ts = get_timestamp();
        flush_streams(ts);
        schedule_retransmit(ts);
    }

    io_result Connection::send(uint8_t* buf, size_t* bufsize, size_t& n_packets, uint64_t ts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(n_packets > 0 && n_packets <= buffer_size);

        auto sent = endpoint.send_packets(path, reinterpret_cast<char*>(buf), bufsize, n_packets);
        if (sent.blocked())
        {
            log::warning(log_cat, "Error: Packet send blocked, scheduling retransmit");
            ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
            schedule_retransmit();
        }
        else if (sent.failure())
        {
            log::warning(log_cat, "Error: I/O error while trying to send packet");
            ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
        }
        else
            n_packets = 0;

        log::trace(log_cat, "Packets away!");
        return sent;
    }

    // Don't worry about seeding this because it doesn't matter at all if the stream selection below
    // is predictable, we just want to shuffle it.
    thread_local std::mt19937 stream_start_rng{};

    int64_t total_packets_like_ever = 0;
    int64_t total_stream_data = 0;
    void Connection::flush_streams(uint64_t ts)
    {
        int debug_stream_packets = 0, debug_stream_mores = 0, debug_streamn1_packets = 0, debug_streamn1_mores = 0;
        // Maximum number of stream data packets to send out at once; if we reach this then we'll
        // schedule another event loop call of ourselves (so that we don't starve the loop)
        const auto max_udp_payload_size = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn.get());
        const auto max_stream_packets = ngtcp2_conn_get_send_quantum(conn.get()) / max_udp_payload_size;
        // packet counter held as member attribute
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        // uint64_t ts = get_timestamp();
        // log::warning(log_cat, "{} called at {}", __PRETTY_FUNCTION__, ts);
        pkt_info = {};

        std::list<Stream*> strs;
        if (!streams.empty())
        {
            // Start from a random stream so that we aren't favouring early streams by potentially
            // giving them more opportunities to send packets.
            auto mid = std::next(
                    streams.begin(), std::uniform_int_distribution<size_t>{0, streams.size() - 1}(stream_start_rng));

            for (auto it = mid; it != streams.end(); ++it)
            {
                auto& stream_ptr = it->second;
                if (stream_ptr and not stream_ptr->sent_fin)
                    strs.push_back(stream_ptr.get());
            }
            for (auto it = streams.begin(); it != mid; ++it)
            {
                auto& stream_ptr = it->second;
                if (stream_ptr and not stream_ptr->sent_fin)
                    strs.push_back(stream_ptr.get());
            }
        }

        std::array<uint8_t, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        size_t n_packets = 0;

        auto* buf_pos = send_buffer.data();

        for (size_t stream_packets = 0; stream_packets < max_stream_packets && !strs.empty(); )
        {
            for (auto it = strs.begin(); it != strs.end();)
            {
                log::trace(log_cat, "Creating packet {} of max {} batch stream packets", n_packets, DATAGRAM_BATCH_SIZE);

                auto& stream = **it;
                auto bufs = stream.pending();

                if (stream.is_closing && !stream.sent_fin && stream.unsent() == 0)
                {
                    log::trace(log_cat, "Sending FIN");
                    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    stream.sent_fin = true;
                }
                else if (bufs.empty())
                {
                    log::debug(log_cat, "pending() returned empty buffer for stream ID {}, moving on", stream.stream_id);
                    it = strs.erase(it);
                    continue;
                }

                /*
                in "for each stream" loop, keep track of whether or not we're in the middle of a
                packet, i.e. when we call write_v stream we are starting (or continuing) a packet,
                and if we call send_packet we finished one.

                then in the next loop (for(;;)), call writev_stream differently based on that, and
                if we send_packet there we're also no longer in the middle of a packet
                */

                ngtcp2_ssize ndatalen;
                auto nwrite = ngtcp2_conn_writev_stream(
                        conn.get(),
                        &path.path,
                        &pkt_info,
                        buf_pos,
                        NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE,
                        &ndatalen,
                        flags,
                        stream.stream_id,
                        bufs.data(),
                        bufs.size(),
                        ts);

                log::trace(log_cat, "add_stream_data for stream {} returned [{},{}]", stream.stream_id, nwrite, ndatalen);

                if (nwrite < 0)
                {
                    if (nwrite == NGTCP2_ERR_WRITE_MORE)  // -240
                    {
                        debug_stream_mores++;
                        log::trace(
                                log_cat, "Consumed {} bytes from stream {} and have space left", ndatalen, stream.stream_id);
                        assert(ndatalen >= 0);
                        stream.wrote(ndatalen);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                    {
                        log::debug(log_cat, "Cannot write to {}: stream is closing", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR)  // -230
                    {
                        log::debug(log_cat, "Cannot add to stream {}: stream is shut, proceeding", stream.stream_id);
                        assert(ndatalen == -1);
                        it = strs.erase(it);
                        continue;
                    }
                    if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                    {
                        log::trace(log_cat, "Cannot add to stream {}: stream is blocked", stream.stream_id);
                        it = strs.erase(it);
                        continue;
                    }

                    log::error(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                    break;
                }

                if (ndatalen >= 0)
                {
                    log::trace(log_cat, "consumed {} bytes from stream {}", ndatalen, stream.stream_id);
                    stream.wrote(ndatalen);
                    total_stream_data += ndatalen;
                }

                if (nwrite == 0)  // we are congested
                {
                    log::trace(log_cat, "Done stream writing to {} (connection is congested)", stream.stream_id);

                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    // we are congested, so clear pending streams to exit outer loop
                    // and enter next loop to flush unsent stuff
                    strs.clear();
                    break;
                }

                debug_stream_packets++;
                buf_pos += nwrite;
                send_buffer_size[n_packets++] = nwrite;
                stream_packets += 1;

                if (n_packets == DATAGRAM_BATCH_SIZE)
                {
                    log::trace(log_cat, "Sending stream data packet batch");
                    if (auto rv = send(send_buffer.data(), send_buffer_size.data(), n_packets, ts); rv.failure())
                    {
                        log::error(log_cat, "Failed to send stream packets: got error code {}", rv.str());
                        return;
                    }

                    buf_pos = send_buffer.data();

                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    if (stream.unsent() == 0)
                        it = strs.erase(it);
                    else
                        ++it;
                }

                if (stream_packets == max_stream_packets)
                {
                    log::trace(log_cat, "Max stream packets ({}) reached", max_stream_packets);
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    return;
                }
            }
        }

        // Now try more with stream id -1 and no data: this takes care of things like initial
        // handshake packets, and also finishes off any partially-filled packet from above.
        for (;;)
        {
            log::trace(log_cat, "Calling add_stream_data for empty stream");

            auto& buf = send_buffer[n_packets];

            ngtcp2_ssize ndatalen;
            auto nwrite = ngtcp2_conn_writev_stream(
                    conn.get(),
                    &path.path,
                    &pkt_info,
                    buf_pos,
                    NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE,
                    &ndatalen,
                    flags,
                    -1,
                    nullptr,
                    0,
                    ts);

            log::trace(log_cat, "add_stream_data for non-stream returned [{},{}]", nwrite, ndatalen);
            assert(ndatalen <= 0);

            if (nwrite == 0)
            {
                log::trace(log_cat, "Nothing else to write for non-stream data for now (or we are congested)");
                break;
            }

            if (nwrite < 0)
            {
                if (nwrite == NGTCP2_ERR_WRITE_MORE)  // -240
                {
                    debug_streamn1_mores++;
                    log::trace(log_cat, "Writing non-stream data frames, and have space left");
                    ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
                    continue;
                }
                if (nwrite == NGTCP2_ERR_CLOSING)  // -230
                {
                    log::warning(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                    break;
                }
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED)  // -210
                {
                    log::info(log_cat, "Cannot add to empty stream right now: stream is blocked");
                    break;
                }

                log::warning(log_cat, "Error writing non-stream data: {}", ngtcp2_strerror(nwrite));
                break;
            }

            debug_streamn1_packets++;
            buf_pos += nwrite;
            send_buffer_size[n_packets++] = nwrite;

            if (n_packets == DATAGRAM_BATCH_SIZE)
            {
                log::trace(log_cat, "Sending packet batch with non-stream data frames");
                if (auto rv = send(send_buffer.data(), send_buffer_size.data(), n_packets, ts); rv.failure())
                    return;

                buf_pos = send_buffer.data();

                ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
            }
        }

        if (n_packets > 0)
        {
            log::trace(log_cat, "Sending packet batch with {} remaining data frames", n_packets);
            if (auto rv = send(send_buffer.data(), send_buffer_size.data(), n_packets, ts); rv.failure())
                return;
            ngtcp2_conn_update_pkt_tx_time(conn.get(), ts);
        }
        log::debug(log_cat, "Exiting flush_streams()");
        /*
        log::warning(log_cat, "flush_streams stats: {} stream more, {} stream packets, {} \"-1\" more, {} \"-1\" packets",
                debug_stream_mores, debug_stream_packets, debug_streamn1_mores, debug_streamn1_packets);
        total_packets_like_ever += debug_stream_packets;
        total_packets_like_ever += debug_stream_mores;
        total_packets_like_ever += debug_streamn1_packets;
        total_packets_like_ever += debug_streamn1_mores;
        log::warning(log_cat, "omg: total packets like ever = {} ({}B), total acks ever = {} ({}B)",
                total_packets_like_ever, total_stream_data, DEBUG_acks, DEBUG_ack_data);
                */
    }

    void Connection::schedule_retransmit(uint64_t ts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto exp = ngtcp2_conn_get_expiry(conn.get());
        // log::warning(log_cat, "ngtcp2 next exp raw: {}", exp);

        if (exp == std::numeric_limits<decltype(exp)>::max())
        {
            log::info(log_cat, "No retransmit needed, expiration passed");
            retransmit_timer->stop();
            return;
        }

        if (ts == 0)
            ts = get_timestamp();

        auto delta = 0;
        if (exp < ts)
        {
            log::info(log_cat, "Expiry delta: {}ns ago", ts - exp);
        }
        else
        {
            delta = exp - ts;
            log::info(log_cat, "Expiry delta: {}ns", delta);
        }

        /*
        log::warning(log_cat, "OMG: {}", fmt::format("{:20d}", fmt::join(OMG_DEBUG, ", ")));
        auto smallest = std::min_element(std::begin(OMG_DEBUG), std::end(OMG_DEBUG));
        std::array<std::string, 8> foo{};
        foo[smallest - std::begin(OMG_DEBUG)] = "^^^^^^^^^^^^^^^^^^^^";
        log::warning(log_cat, "omg: {}", fmt::format("{:20}", fmt::join(foo, "  ")));
        */

        // truncate to ms for libuv
        delta /= 1'000'000;

        retransmit_timer->stop();
        retransmit_timer->start(delta * 1ms, 0ms);
    }

    const std::shared_ptr<Stream>& Connection::get_stream(int64_t ID) const
    {
        return streams.at(ID);
    }

    int Connection::stream_opened(int64_t id)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::info(log_cat, "New stream ID:{}", id);

        auto stream = std::make_shared<Stream>(*this, id);

        stream->stream_id = id;
        uint64_t rv{0};

        auto srv = stream->conn.server();

        if (srv)
        {
            stream->data_callback = srv->context->stream_data_cb;

            if (srv->context->stream_open_cb)
                rv = srv->context->stream_open_cb(*stream);
        }

        if (rv != 0)
        {
            log::info(log_cat, "stream_open_callback returned failure, dropping stream {}", id);
            ngtcp2_conn_shutdown_stream(conn.get(), 0, id, 1);
            io_ready();
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        auto [it, ins] = streams.emplace(id, std::move(stream));
        assert(ins);
        log::info(log_cat, "Created new incoming stream {}", id);
        return 0;
    }

    void Connection::stream_closed(int64_t id, uint64_t app_code)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(ngtcp2_is_bidi_stream(id));
        log::info(log_cat, "Stream {} closed with code {}", id, app_code);
        auto it = streams.find(id);

        if (it == streams.end())
            return;

        auto& stream = *it->second;
        const bool was_closing = stream.is_closing;
        stream.is_closing = stream.is_shutdown = true;

        if (!was_closing && stream.close_callback)
        {
            log::trace(log_cat, "Invoking stream close callback");
            std::optional<uint64_t> code;
            if (app_code != 0)
                code = app_code;
            stream.close_callback(stream, *code);
        }

        log::info(log_cat, "Erasing stream {}", id);
        streams.erase(it);

        if (!ngtcp2_conn_is_local_stream(conn.get(), id))
            ngtcp2_conn_extend_max_streams_bidi(conn.get(), 1);

        io_ready();
    }

    int Connection::stream_ack(int64_t id, size_t size)
    {
        if (auto it = streams.find(id); it != streams.end())
        {
            it->second->acknowledge(size);
            return 0;
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int Connection::stream_receive(int64_t id, bstring_view data, bool fin)
    {
        auto str = get_stream(id);

        if (!str->data_callback)
            log::debug(log_cat, "Stream (ID: {}) has no user-supplied data callback", str->stream_id);
        else
        {
            bool good = false;

            try
            {
                str->data_callback(*str, data);
                good = true;
            }
            catch (const std::exception& e)
            {
                log::warning(
                        log_cat,
                        "Stream {} data callback raised exception ({}); closing stream with app "
                        "code "
                        "{}",
                        str->stream_id,
                        e.what(),
                        STREAM_ERROR_EXCEPTION);
            }
            catch (...)
            {
                log::warning(
                        log_cat,
                        "Stream {} data callback raised an unknown exception; closing stream with "
                        "app "
                        "code {}",
                        str->stream_id,
                        STREAM_ERROR_EXCEPTION);
            }
            if (!good)
            {
                str->close(STREAM_ERROR_EXCEPTION);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }

        if (fin)
        {
            log::info(log_cat, "Stream {} closed by remote", str->stream_id);
            // no clean up, close_cb called after this
        }
        else
        {
            ngtcp2_conn_extend_max_stream_offset(conn.get(), id, data.size());
            ngtcp2_conn_extend_max_offset(conn.get(), data.size());
        }

        return 0;
    }

    int Connection::get_streams_available()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        uint64_t open = ngtcp2_conn_get_streams_bidi_left(conn.get());
        if (open > std::numeric_limits<uint64_t>::max())
            return -1;
        return static_cast<int>(open);
    }

    int Connection::init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks)
    {
        auto loop = quic_manager->loop();
        io_trigger = loop->resource<uvw::async_handle>();
        io_trigger->on<uvw::async_event>([this](auto&, auto&) {
            // log::warning(log_cat, "io trigger fired at {}ns", get_timestamp());
            on_io_ready();
        });

        retransmit_timer = loop->resource<uvw::timer_handle>();
        retransmit_timer->on<uvw::timer_event>([this](auto&, auto&) {
            /*
            log::warning(
                    log_cat, "Retransmit timer fired at {}ns", std::chrono::steady_clock::now().time_since_epoch().count());
            */
            if (auto rv = ngtcp2_conn_handle_expiry(conn.get(), get_timestamp()); rv != 0)
            {
                log::warning(log_cat, "Error: expiry handler invocation returned error code: {}", ngtcp2_strerror(rv));
                endpoint.close_connection(*this, rv);
            }
            else
            {
                on_io_ready();
            }
        });

        retransmit_timer->start(0ms, 0ms);

        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = recv_stream_data;
        callbacks.acked_stream_data_offset = acked_stream_data_offset;
        callbacks.stream_close = on_stream_close;
        callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi;
        callbacks.rand = rand_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.stream_reset = on_stream_reset;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        // callbacks.recv_rx_key = recv_rx_key;
        // callbacks.recv_tx_key = recv_tx_key;
        // callbacks.dcid_status = NULL;
        // callbacks.handshake_completed = NULL;
        // callbacks.handshake_confirmed = NULL;

        ngtcp2_settings_default(&settings);

        settings.initial_ts = get_timestamp();
#ifndef NDEBUG
        settings.log_printf = log_printer;
#endif
        settings.max_tx_udp_payload_size = NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE;
        settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;

        ngtcp2_transport_params_default(&params);

        // Connection flow level control window
        params.initial_max_data = 1_MiB;
        // Max concurrent streams supported on one connection
        params.initial_max_streams_uni = 0;
        params.initial_max_streams_bidi = 32;
        // Max send buffer for streams (local = streams we initiate, remote = streams initiated to
        // us)
        params.initial_max_stream_data_bidi_local = 64_kiB;
        params.initial_max_stream_data_bidi_remote = 64_kiB;
        params.max_idle_timeout = std::chrono::nanoseconds(5min).count();
        params.active_connection_id_limit = 8;

        return 0;
    }

    // client conn
    Connection::Connection(
            Client& client,
            std::shared_ptr<Handler> ep,
            const ConnectionID& scid,
            const Path& path,
            std::shared_ptr<uvw::udp_handle> handle) :
            endpoint{client},
            quic_manager{ep},
            source_cid{scid},
            dest_cid{ConnectionID::random()},
            path{path},
            local{client.context->local},
            remote{client.context->remote},
            udp_handle{handle},
            tls_context{client.context->tls_ctx}
    {
        log::trace(log_cat, "Creating new client connection object");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;

        if (auto rv = init(settings, params, callbacks); rv != 0)
            log::warning(log_cat, "Error: Client-based connection not created");

        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;

        int rv = ngtcp2_conn_client_new(
                &connptr, &dest_cid, &source_cid, path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

        // set conn_ref fxn to return ngtcp2_crypto_conn_ref
        tls_context->conn_ref.get_conn = get_conn;
        // store pointer to connection in user_data
        tls_context->conn_ref.user_data = this;

        ngtcp2_conn_set_tls_native_handle(connptr, tls_context->session);
        conn.reset(connptr);

        if (rv != 0)
        {
            throw std::runtime_error{"Failed to initialize client connection to server: "s + ngtcp2_strerror(rv)};
        }

        log::info(log_cat, "Successfully created new client connection object");
    }

    // server conn
    Connection::Connection(
            Server& server,
            std::shared_ptr<Handler> ep,
            const ConnectionID& cid,
            ngtcp2_pkt_hd& hdr,
            const Path& path,
            std::shared_ptr<TLSContext> ctx) :
            endpoint{server},
            quic_manager{ep},
            source_cid{cid},
            dest_cid{hdr.scid},
            path{path},
            local{server.context->local},
            remote{path.remote},
            tls_context{ctx}
    {
        log::trace(log_cat, "Creating new server connection object");

        ngtcp2_settings settings;
        ngtcp2_transport_params params;
        ngtcp2_callbacks callbacks{};
        ngtcp2_conn* connptr;

        if (auto rv = init(settings, params, callbacks); rv != 0)
            log::warning(log_cat, "Error: Server-based connection not created");

        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.stream_open = on_stream_open;

        params.original_dcid = hdr.dcid;
        params.original_dcid_present = 1;

        settings.token = hdr.token;

        int rv = ngtcp2_conn_server_new(
                &connptr, &dest_cid, &source_cid, path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, this);

        // set conn_ref fxn to return ngtcp2_crypto_conn_ref
        tls_context->conn_ref.get_conn = get_conn;
        // store pointer to connection in user_data
        tls_context->conn_ref.user_data = this;

        ngtcp2_conn_set_tls_native_handle(connptr, tls_context->session);
        conn.reset(connptr);

        if (rv != 0)
        {
            throw std::runtime_error{"Failed to initialize server connection to client: "s + ngtcp2_strerror(rv)};
        }

        log::info(log_cat, "Successfully created new server connection object");
    }

    Connection::~Connection()
    {
        if (io_trigger)
            io_trigger->close();
        if (retransmit_timer)
        {
            retransmit_timer->stop();
            retransmit_timer->close();
        }
    }

}  // namespace oxen::quic
