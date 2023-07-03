#include "endpoint.hpp"

extern "C"
{
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/version.h>
#ifdef __linux__
#include <netinet/udp.h>
#endif
}

#include <cstddef>
#include <list>
#include <optional>

#include "connection.hpp"
#include "internal.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    Endpoint::Endpoint(Network& n, const Address& listen_addr) : net{n}, _local{listen_addr}
    {
        log::debug(log_cat, "Starting new UDP socket on {}", _local);
        socket = std::make_unique<UDPSocket>(get_loop().get(), _local, [this](const auto& packet) { handle_packet(packet); });

        expiry_timer.reset(event_new(
                get_loop().get(),
                -1,          // Not attached to an actual socket
                EV_PERSIST,  // Stays active (i.e. repeats) once fired
                [](evutil_socket_t, short, void* self) { static_cast<Endpoint*>(self)->check_timeouts(); },
                this));
        timeval exp_interval;
        exp_interval.tv_sec = 0;
        exp_interval.tv_usec = 250'000;
        event_add(expiry_timer.get(), &exp_interval);

        log::info(log_cat, "Created QUIC endpoint listening on {}", _local);
    }

    std::list<std::shared_ptr<connection_interface>> Endpoint::get_all_conns(std::optional<Direction> d)
    {
        std::list<std::shared_ptr<connection_interface>> ret{};

        for (const auto& c : conns)
        {
            if (d)
            {
                if (c.second->direction() == d)
                    ret.emplace_back(c.second);
            }
            else
                ret.emplace_back(c.second);
        }

        return ret;
    }

    void Endpoint::close_conns(std::optional<Direction> d)
    {
        for (const auto& c : conns)
        {
            if (d)
            {
                if (c.second->direction() == d)
                    close_connection(*c.second.get());
            }
            else
                close_connection(*c.second.get());
        }
    }

    void Endpoint::drain_connection(Connection& conn)
    {
        if (conn.is_draining())
            return;
        conn.call_closing();

        log::debug(log_cat, "Putting CID: {} into draining state", conn.scid());
        conn.drain();
        draining.emplace(get_time() + ngtcp2_conn_get_pto(conn) * 3 * 1ns, conn.scid());
    }

    void Endpoint::handle_packet(const Packet& pkt)
    {
        auto dcid_opt = handle_packet_connid(pkt);

        if (!dcid_opt)
        {
            log::warning(log_cat, "Error: initial packet handling failed");
            return;
        }

        auto& dcid = *dcid_opt;

        // check existing conns
        log::trace(log_cat, "Incoming connection ID: {}", dcid);
        auto cptr = get_conn(dcid);

        if (!cptr)
        {
            if (accepting_inbound)
            {
                cptr = accept_initial_connection(pkt);

                if (!cptr)
                {
                    log::warning(log_cat, "Error: connection could not be created");
                    return;
                }
            }
            else
            {
                log::warning(log_cat, "Dropping packet; unknown connection ID (and we aren't accepting inbound conns)");
                return;
            }
        }

        handle_conn_packet(*cptr, pkt);
        return;
    }

    void Endpoint::close_connection(Connection& conn, int code, std::string_view msg)
    {
        log::debug(log_cat, "Closing connection (CID: {})", *conn.scid().data);

        if (conn.is_closing() || conn.is_draining())
            return;

        if (code == NGTCP2_ERR_IDLE_CLOSE)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now without close "
                    "packet",
                    *conn.scid().data);
            delete_connection(conn.scid());
            return;
        }

        //  "The error not specifically mentioned, including NGTCP2_ERR_HANDSHAKE_TIMEOUT,
        //  should be dealt with by calling ngtcp2_conn_write_connection_close."
        //  https://github.com/ngtcp2/ngtcp2/issues/670#issuecomment-1417300346
        if (code == NGTCP2_ERR_HANDSHAKE_TIMEOUT)
        {
            log::info(
                    log_cat,
                    "Connection (CID: {}) passed idle expiry timer; closing now with close packet",
                    *conn.scid().data);
        }

        ngtcp2_ccerr err;
        ngtcp2_ccerr_set_liberr(&err, code, reinterpret_cast<uint8_t*>(const_cast<char*>(msg.data())), msg.size());

        std::vector<std::byte> buf;
        buf.resize(max_payload_size);
        ngtcp2_pkt_info pkt_info{};

        auto written = ngtcp2_conn_write_connection_close(
                conn, nullptr, &pkt_info, u8data(buf), buf.size(), &err, get_timestamp().count());

        if (written <= 0)
        {
            log::warning(
                    log_cat,
                    "Error: Failed to write connection close packet: {}",
                    (written < 0) ? strerror(written) : "[Error Unknown: closing pkt is 0 bytes?]"s);

            delete_connection(conn.scid());
            return;
        }
        // ensure we had enough write space
        assert(static_cast<size_t>(written) <= buf.size());

        send_or_queue_packet(conn.path(), std::move(buf), /*ecn=*/0, [this, cid = conn.scid()](io_result rv) {
            if (rv.failure())
            {
                log::warning(
                        log_cat, "Error: failed to send close packet [{}]; removing connection [CID: {}]", rv.str_error(), cid);
                delete_connection(cid);
            }
        });
    }

    void Endpoint::delete_connection(const ConnectionID& cid)
    {
        if (auto itr = conns.find(cid); itr != conns.end())
        {
            itr->second->call_closing();

            conns.erase(itr);
            log::debug(log_cat, "Successfully deleted connection [ID: {}]", *cid.data);
        }
        else
            log::warning(log_cat, "Error: could not delete connection [ID: {}]; could not find", *cid.data);
    }

    std::optional<ConnectionID> Endpoint::handle_packet_connid(const Packet& pkt)
    {
        ngtcp2_version_cid vid;
        auto rv = ngtcp2_pkt_decode_version_cid(&vid, u8data(pkt.data), pkt.data.size(), NGTCP2_MAX_CIDLEN);

        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {  // version negotiation has not been sent yet, ignore packet
            send_version_negotiation(vid, pkt.path);
            return std::nullopt;
        }
        if (rv != 0)
        {
            log::debug(log_cat, "Error: failed to decode QUIC packet header [code: {}]", ngtcp2_strerror(rv));
            return std::nullopt;
        }

        if (vid.dcidlen > NGTCP2_MAX_CIDLEN)
        {
            log::debug(
                    log_cat,
                    "Error: destination ID is longer than NGTCP2_MAX_CIDLEN ({} > {})",
                    vid.dcidlen,
                    NGTCP2_MAX_CIDLEN);
            return std::nullopt;
        }

        return std::make_optional<ConnectionID>(vid.dcid, vid.dcidlen);
    }

    Connection* Endpoint::accept_initial_connection(const Packet& pkt)
    {
        log::info(log_cat, "Accepting new connection...");

        ngtcp2_pkt_hd hdr;

        auto rv = ngtcp2_accept(&hdr, u8data(pkt.data), pkt.data.size());

        if (rv < 0)  // catches all other possible ngtcp2 errors
        {
            log::warning(
                    log_cat,
                    "Warning: unexpected packet received, length={}, code={}, continuing...",
                    pkt.data.size(),
                    ngtcp2_strerror(rv));
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_0RTT)
        {
            log::error(log_cat, "Error: 0RTT is not utilized in this implementation; dropping packet");
            return nullptr;
        }
        if (hdr.type == NGTCP2_PKT_INITIAL && hdr.tokenlen)
        {
            log::warning(log_cat, "Warning: Unexpected token in initial packet");
            return nullptr;
        }

        assert(net.in_event_loop());
        for (;;)
        {
            if (auto [itr, success] = conns.emplace(ConnectionID::random(), nullptr); success)
            {
                itr->second =
                        Connection::make_conn(*this, itr->first, hdr.scid, pkt.path, inbound_ctx, Direction::INBOUND, &hdr);
                return itr->second.get();
            }
        }
    }

    void Endpoint::handle_conn_packet(Connection& conn, const Packet& pkt)
    {
        if (auto rv = ngtcp2_conn_in_closing_period(conn); rv != 0)
        {
            log::debug(log_cat, "Error: connection (CID: {}) is in closing period; dropping connection", *conn.scid().data);
            delete_connection(conn.scid());
            return;
        }

        if (conn.is_draining())
        {
            log::debug(log_cat, "Error: connection is already draining; dropping");
        }

        // TODO: if read packet gives us failure, should we close?
        if (read_packet(conn, pkt).success())
            log::trace(log_cat, "done with incoming packet");
        else
            log::trace(log_cat, "read packet failed");  // error will be already logged
    }

    io_result Endpoint::read_packet(Connection& conn, const Packet& pkt)
    {
        auto ts = get_timestamp().count();
        auto rv = ngtcp2_conn_read_pkt(conn, pkt.path, &pkt.pkt_info, u8data(pkt.data), pkt.data.size(), ts);

        switch (rv)
        {
            case 0:
                conn.io_ready();
                break;
            case NGTCP2_ERR_DRAINING:
                log::debug(log_cat, "Draining connection {}", *conn.scid().data);
                drain_connection(conn);
                break;
            case NGTCP2_ERR_PROTO:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.scid().data, ngtcp2_strerror(rv));
                close_connection(conn, rv, "ERR_PROTO"sv);
                break;
            case NGTCP2_ERR_DROP_CONN:
                // drop connection without calling ngtcp2_conn_write_connection_close()
                log::debug(log_cat, "Dropping connection {} due to error {}", *conn.scid().data, ngtcp2_strerror(rv));
                delete_connection(conn.scid());
                break;
            case NGTCP2_ERR_CRYPTO:
                // drop conn without calling ngtcp2_conn_write_connection_close()
                log::debug(
                        log_cat,
                        "Dropping connection {} due to error {} (code: {})",
                        *conn.scid().data,
                        ngtcp2_conn_get_tls_alert(conn),
                        ngtcp2_strerror(rv));
                delete_connection(conn.scid());
                break;
            default:
                log::debug(log_cat, "Closing connection {} due to error {}", *conn.scid().data, ngtcp2_strerror(rv));
                close_connection(conn, rv, ngtcp2_strerror(rv));
                break;
        }

        return io_result::ngtcp2(rv);
    }

    io_result Endpoint::send_packets(const Address& dest, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(log_cat, "Cannot send packets on closed socket (to reach {})", dest);
            return io_result{EBADF};
        }
        assert(n_pkts >= 1 && n_pkts <= MAX_BATCH);

        log::trace(log_cat, "Sending {} UDP packet(s) to {}...", n_pkts, dest);

        auto [ret, sent] = socket->send(dest, buf, bufsize, ecn, n_pkts);

        if (ret.failure() && !ret.blocked())
        {
            log::error(log_cat, "Error sending packets to {}: {}", dest, ret.str_error());
            n_pkts = 0;  // Drop any packets, as we had a serious error
            return ret;
        }

        if (sent < n_pkts)
        {
            if (sent == 0)  // Didn't send *any* packets, i.e. we got entirely blocked
                log::debug(log_cat, "UDP sent none of {}", n_pkts);

            else
            {
                // We sent some but not all, so shift the unsent packets back to the beginning of buf/bufsize
                log::debug(log_cat, "UDP undersent {}/{}", sent, n_pkts);
                size_t offset = std::accumulate(bufsize, bufsize + sent, size_t{0});
                size_t len = std::accumulate(bufsize + sent, bufsize + n_pkts, size_t{0});
                std::memmove(buf, buf + offset, len);
                std::copy(bufsize + sent, bufsize + n_pkts, bufsize);
                n_pkts -= sent;
            }

            // We always return EAGAIN (so that .blocked() is true) if we failed to send all, even
            // if that isn't strictly what we got back as the return value (sendmmsg gives back a
            // non-error on *partial* success).
            return io_result{EAGAIN};
        }
        else
            n_pkts = 0;

        return ret;
    }

    void Endpoint::send_or_queue_packet(
            const Path& p, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(log_cat, "Cannot sent to dead socket for path {}", p);
            if (callback)
                callback(io_result{EBADF});
            return;
        }

        size_t n_pkts = 1;
        size_t bufsize = buf.size();
        auto res = send_packets(p.remote, buf.data(), &bufsize, ecn, n_pkts);

        if (res.blocked())
        {
            socket->when_writeable([this, p, buf = std::move(buf), ecn, cb = std::move(callback)]() mutable {
                send_or_queue_packet(p, std::move(buf), ecn, std::move(cb));
            });
        }
    }

    void Endpoint::send_version_negotiation(const ngtcp2_version_cid& vid, const Path& p)
    {
        uint8_t rint;
        gnutls_rnd(GNUTLS_RND_RANDOM, &rint, 8);
        std::vector<std::byte> buf;
        buf.resize(max_payload_size);
        std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
        std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
        // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
        versions[0] = 0x1a2a3a4au;

        auto nwrite = ngtcp2_pkt_write_version_negotiation(
                u8data(buf),
                buf.size(),
                rint,
                vid.dcid,
                vid.dcidlen,
                vid.scid,
                vid.scidlen,
                versions.data(),
                versions.size());
        if (nwrite <= 0)
        {
            log::warning(log_cat, "Error: Failed to construct version negotiation packet: {}", ngtcp2_strerror(nwrite));
            return;
        }

        send_or_queue_packet(p, std::move(buf), /*ecn=*/0);
    }

    void Endpoint::check_timeouts()
    {
        auto now = get_time();

        const auto& f = draining.begin();

        while (!draining.empty() && f->first < now)
        {
            if (auto itr = conns.find(f->second); itr != conns.end())
            {
                log::debug(log_cat, "Deleting connection {}", *itr->first.data);
                conns.erase(itr);
            }
            draining.erase(f);
        }
    }

    Connection* Endpoint::get_conn(const ConnectionID& id)
    {
        if (auto it = conns.find(id); it != conns.end())
            return it->second.get();
        return nullptr;
    }

    bool Endpoint::in_event_loop() const
    {
        return net.in_event_loop();
    }

}  // namespace oxen::quic
