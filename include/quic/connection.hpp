#pragma once

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <uvw.hpp>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint;
    class Stream;
	class connection_interface;

    class Connection : public std::enable_shared_from_this<Connection>
    {
      protected:
        friend class Network;
		friend class Endpoint;
		friend class connection_interface;

		using conn_ptr_pair = std::pair<std::shared_ptr<Connection>, std::shared_ptr<connection_interface>>;

		static conn_ptr_pair make_inbound_conn_pair(Endpoint& ep, 
				const ConnectionID& scid,
				const ConnectionID& dcid,
				const Address& local,
				const Address& remote,
				const Path& path,
				std::shared_ptr<uv_udp_t> handle,
				std::shared_ptr<TLSContext> ctx,
				config_t u_config)
		{
			return _make_conn_pair(ep, scid, dcid, local, remote, path, handle, ctx, u_config, INBOUND);
		};

		static conn_ptr_pair make_outbound_conn_pair(Endpoint& ep, 
				const ConnectionID& scid,
				const ConnectionID& dcid,
				const Address& local,
				const Address& remote,
				const Path& path,
				std::shared_ptr<uv_udp_t> handle,
				std::shared_ptr<TLSContext> ctx,
				config_t u_config)
		{
			return _make_conn_pair(ep, scid, dcid, local, remote, path, handle, ctx, u_config, OUTBOUND);
		};

        std::shared_ptr<Stream> _get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);
      
	  private:

        std::shared_ptr<uv_udp_t> udp_handle;
        config_t user_config;
		Direction direction;
        Endpoint& _endpoint;
        const ConnectionID source_cid;
        ConnectionID dest_cid;
        Path path;
		const Address _local;
        const Address _remote;

		static conn_ptr_pair _make_conn_pair(Endpoint& ep, 
				const ConnectionID& scid,
				const ConnectionID& dcid,
				const Address& local,
				const Address& remote,
				const Path& path,
				std::shared_ptr<uv_udp_t> handle,
				std::shared_ptr<TLSContext> ctx,
				config_t u_config,
				Direction dir);

        struct connection_deleter
        {
            inline void operator()(ngtcp2_conn* c) const { ngtcp2_conn_del(c); }
        };

        int init(ngtcp2_settings& settings, ngtcp2_transport_params& params, ngtcp2_callbacks& callbacks);

        // underlying ngtcp2 connection object
        std::unique_ptr<ngtcp2_conn, connection_deleter> conn;
        std::shared_ptr<TLSContext> tls_context;
        
      public:

        std::shared_ptr<uvw::timer_handle> retransmit_timer;

        // Construct and initialize a new inbound/outbound connection to/from a remote
        //      ep: owning endpoints
        //      scid: local ("primary") CID used for this connection (random for outgoing)
		//		dcid: remote CID used for this connection
		//		local_addr: local address bound to udp handle
		//		remote_addr: remote address we are communicating to
        //      path: network path used to reach remote client
		//		handle: udp handle dedicated to local address
		//		ctx: connection context
		//		u_config: user configuration values passed in struct
		//		tok: optional parameter for inbound connections to be passed to ngtcp2
		Connection(Endpoint& ep, 
				const ConnectionID& scid,
				const ConnectionID& dcid,
				const Address& local_addr,
				const Address& remote_addr,
				const Path& path,
				std::shared_ptr<uv_udp_t> handle,
				std::shared_ptr<TLSContext> ctx,
				config_t u_config,
				Direction dir,
				const uint8_t* tok = nullptr);

        ~Connection();

        // Callbacks to be invoked if set
        std::function<void(Connection&)> on_closing;  // clear immediately after use

        // change to check_pending_streams, do not create after while loop
        void check_pending_streams(
                int available, stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);


        void on_io_ready();

        struct pkt_tx_timer_updater;
        bool send(pkt_tx_timer_updater* pkt_updater = nullptr);

        void flush_streams(uint64_t ts);

        void io_ready();

        std::array<uint8_t, NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE * DATAGRAM_BATCH_SIZE> send_buffer;
        std::array<size_t, DATAGRAM_BATCH_SIZE> send_buffer_size;
        size_t n_packets = 0;
        uint8_t* send_buffer_pos = send_buffer.data();

        // Returns a pointer to the owning endpoint, else nullptr
        Endpoint* endpoint();
        const Endpoint* endpoint() const;

        void schedule_retransmit(uint64_t ts = 0);

        const std::shared_ptr<Stream>& get_stream(int64_t ID) const;

        int stream_opened(int64_t id);

        int stream_ack(int64_t id, size_t size);

        int stream_receive(int64_t id, bstring_view data, bool fin);

        void stream_closed(int64_t id, uint64_t app_code);

        int get_streams_available();

        // Buffer used to store non-stream connection data
        //  ex: initial transport params
        bstring conn_buffer;

        bool draining = false;
        bool closing = false;


        // holds a mapping of active streams
        std::map<int64_t, std::shared_ptr<Stream>> streams;
        // holds queue of pending streams not yet ready to broadcast
        // streams are added to the back and popped from the front (FIFO)
        std::deque<std::shared_ptr<Stream>> pending_streams;

        ngtcp2_ccerr last_error;

        std::shared_ptr<uvw::async_handle> io_trigger;

        // pass Connection as ngtcp2_conn object
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator const T*() const
        {
            return conn.get();
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_conn>, int> = 0>
        operator T*()
        {
            return conn.get();
        }
    };

	class connection_interface
    {
      public:
        explicit connection_interface(Endpoint& e, Connection& c_ref) : 
				ep{e}, conn{c_ref.weak_from_this()}, scid{c_ref.source_cid}, dcid{c_ref.dest_cid} 
		{ }

		connection_interface(const connection_interface& obj) :
				ep{obj.ep}, conn{obj.conn}, scid{obj.scid}, dcid{obj.dcid} 
		{}


		std::shared_ptr<Stream> get_new_stream(
                stream_data_callback_t data_cb = nullptr, stream_close_callback_t close_cb = nullptr);

      private:
		Endpoint& ep;
		const ConnectionID scid;
		const ConnectionID dcid;
        std::weak_ptr<Connection> conn;
    };

    extern "C"
    {
        ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref);

        void log_printer(void* user_data, const char* fmt, ...);
    }

}  // namespace oxen::quic
