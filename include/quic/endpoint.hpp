#pragma once

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
}

#include <cstddef>
#include <memory>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <string>
#include <unordered_map>
#include <uvw.hpp>

#include "network.hpp"
#include "connection.hpp"
#include "context.hpp"
#include "utils.hpp"

namespace oxen::quic
{
	using conn_ptr_pair = std::pair<std::shared_ptr<Connection>, std::shared_ptr<connection_interface>>;

    class Endpoint : std::enable_shared_from_this<Endpoint>
    {
		friend class Network;
        friend class Connection;
		friend class Stream;

      private:
		const Address local;
        std::shared_ptr<uvw::timer_handle> expiry_timer;
        std::shared_ptr<uv_udp_t> handle;
		config_t user_config{};
		bool accepting_inbound{false};
        Network& net;

      public:
        explicit Endpoint(Network& n, const Address& listen_addr);

		template <typename... Opt>
		bool inbound_init(Opt&&... opts)
		{
			std::promise<bool> p;
			auto f = p.get_future();

			net.call([&opts..., &p, this]() mutable {
				try
				{
					// initialize client context and client tls context simultaneously
					inbound_ctx = std::make_shared<InboundContext>(std::forward<Opt>(opts)...);
					accepting_inbound = true;

					log::debug(log_cat, "Inbound context ready for incoming connections");

					p.set_value(true);
				}
				catch (...)
				{
					p.set_exception(std::current_exception());
				}
			});

			return f.get();
		}


        // creates new outbound connection to remote; emplaces conn/interface pair in outbound map
		template <typename... Opt>
        std::shared_ptr<connection_interface> connect(const Address& remote, Opt&&... opts)
		{
			std::promise<std::shared_ptr<connection_interface>> p;
			auto f = p.get_future();

			net.call([&opts..., &p, this, raddr = remote]() mutable {
				try
				{
					// initialize client context and client tls context simultaneously
					outbound_ctx = std::make_shared<OutboundContext>(std::forward<Opt>(opts)...);

					if (auto [itr, res] = outbound_conns.emplace(std::piecewise_construct,
						std::forward_as_tuple(ConnectionID::random()), std::forward_as_tuple(nullptr, nullptr)); res)
					{
						itr->second = std::move(Connection::make_outbound_conn_pair(
							*this,
							itr->first,
							ConnectionID::random(),
							Path{local, raddr},
							handle,
							outbound_ctx->tls_creds,
							user_config
						));

						p.set_value(itr->second.second);
					}
					else
						p.set_value(nullptr);
				}
				catch (...)
				{
					p.set_exception(std::current_exception());
				}
			});

			return f.get();
		};

        std::shared_ptr<uvw::loop> get_loop();

        Connection* get_conn_ptr(ConnectionID ID);		// query by conn ID
        Connection* get_conn_ptr(const Address& addr);	// query by remote addr

		// query a list of all active inbound and outbound connections paired with a conn_interface
        std::list<std::pair<ConnectionID, std::shared_ptr<connection_interface>>> get_all_inbounds();
		std::list<std::pair<ConnectionID, std::shared_ptr<connection_interface>>> get_all_outbounds();

		std::pair<ConnectionID, std::shared_ptr<connection_interface>> get_inbound_conn();
		std::pair<ConnectionID, std::shared_ptr<connection_interface>> get_outbound_conn();

        std::shared_ptr<uv_udp_t> get_handle();
        
		void handle_packet(Packet& pkt);

      protected:

	  	std::shared_ptr<ContextBase> outbound_ctx = nullptr;
	  	std::shared_ptr<ContextBase> inbound_ctx = nullptr;


        void close_connection(Connection& conn, int code = NGTCP2_NO_ERROR, std::string_view msg = "NO_ERROR"sv);

        void delete_connection(const ConnectionID& cid);
        
		void close_conns();

        // Data structures used to keep track of various types of connections
        //
        // {inbound,outbound}_conns:
        //      When a client establishes a new connection, it provides its own source CID (scid)
        //      and destination CID (dcid), which it sends to the server. The primary Connection
        //      instance is stored as a shared_ptr indexd by scid
        //          dcid is entirely random string of <=160 bits
        //          scid can be random or store information
        //
        //          When responding, the server will include in its response:
        //          - dcid equal to client's source CID
        //          - New random scid; the client's dcid is not used. This
        //              can also store data like the client's scid
        //
        //          As a result, we end up with:
        //              client.scid == server.dcid
        //              client.dcid == server.scid
        //          with each side randomizing their own scid
        //
        // draining:
        //      Stores all connections that are labeled as draining (duh). They are kept around for
        //      a short period of time allowing any lagging packets to be caught
        //
        //      They are indexed by connection ID, storing the removal time as a uint64_t value
        std::unordered_map<ConnectionID, conn_ptr_pair> inbound_conns;
        std::unordered_map<ConnectionID, conn_ptr_pair> outbound_conns;

        std::queue<std::pair<ConnectionID, uint64_t>> draining;

        std::optional<ConnectionID> handle_initial_packet(Packet& pkt);

        void handle_conn_packet(Connection& conn, Packet& pkt);

        io_result read_packet(Connection& conn, Packet& pkt);

        io_result send_packets(Path& p, char* buf, size_t* bufsize, size_t& n_pkts);
        io_result send_packet_libuv(Path& p, const char* buf, size_t bufsize, std::function<void()> after_sent = nullptr);

        io_result send_packet(Path& p, bstring_view data);

        void send_version_negotiation(const ngtcp2_version_cid& vid, Path& p);

        void check_timeouts();

        // Accepts new connection, returning either a ptr to the Connection
        // object or nullptr if error. Virtual function returns nothing --
        // overrided by Client and Server classes
        Connection* accept_initial_connection(Packet& pkt, ConnectionID& dcid);

	  private:
	  	//
    };

}  // namespace oxen::quic
