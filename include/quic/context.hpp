#pragma once

#include <memory>
#include <unordered_map>
#include <uvw.hpp>

#include "crypto.hpp"
#include "opt.hpp"
#include "stream.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    class Endpoint;

    // created to store user configuration values; more values to be added later
    struct config_t
    {
        // max streams
        int max_streams = 0;

        config_t() = default;
    };

    struct SessionBase
    {
	  public:
        Address local, remote;
        std::shared_ptr<Handler> quic_manager;
        std::shared_ptr<TLSCreds> tls_creds;
        config_t config{};

        virtual ~ContextBase() = default;

        virtual std::shared_ptr<Endpoint> endpoint() = 0;
    };

    struct ClientContext : public ContextBase
    {
        // Cert information for each connection is stored in a map indexed by ConnectionID.
        // As a result, each connection (also mapped in client->conns) can have its own
        // TLS cert info. Each connection also stores within it the gnutls_session_t and
        // gnutls_certificate_credentials_t objects used to initialize its ngtcp2 things
        std::shared_ptr<Client> client;
        std::shared_ptr<uv_udp_t> udp_handle;
        ConnectionID conn_id;
        stream_data_callback_t stream_data_cb;
        stream_open_callback_t stream_open_cb;

		template <typename... Opt>
        SessionBase(Opt&&... opts)
		{
            log::trace(log_cat, "Making endpoint session context...");
            // parse all options
            ((void)handle_session_opt(std::forward<Opt>(opts)), ...);

            log::debug(log_cat, "Endpoint session context created successfully");
		}

        inline std::shared_ptr<Endpoint> endpoint() { return _endpoint; };

      private:
        void handle_clientctx_opt(opt::local_addr addr);
        void handle_clientctx_opt(opt::remote_addr addr);
        void handle_clientctx_opt(std::shared_ptr<TLSCreds> tls);
        void handle_clientctx_opt(opt::max_streams ms);
        void handle_clientctx_opt(stream_data_callback_t func);
        void handle_clientctx_opt(stream_open_callback_t func);

        inline void set_local(Address& addr) { local = Address{addr}; }
        inline void set_remote(Address& addr) { remote = Address{addr}; }
    };

    struct ServerContext : public ContextBase
    {
        std::shared_ptr<Server> server;
        std::unordered_map<Address, std::pair<std::shared_ptr<uv_udp_t>, std::shared_ptr<TLSCreds>>> udp_handles;
        stream_data_callback_t stream_data_cb;
        stream_open_callback_t stream_open_cb;

        // Server endpoint linked to this instance
        std::shared_ptr<Endpoint> endpoint() override;

        template <typename... Opt>
        ServerContext(std::shared_ptr<Handler> quic_ep, Opt&&... opts)
        {
            log::trace(log_cat, "Making server context...");

            // copy assign handler shared_ptr
            quic_manager = quic_ep;
            // parse all options
            ((void)handle_serverctx_opt(std::forward<Opt>(opts)), ...);

            log::debug(log_cat, "Server context successfully created");
        }

      private:
        void handle_serverctx_opt(opt::local_addr addr);
        void handle_serverctx_opt(Address addr);
        void handle_serverctx_opt(std::shared_ptr<TLSCreds> tls);
        void handle_serverctx_opt(stream_data_callback_t func);
        void handle_serverctx_opt(stream_open_callback_t func);
        void handle_serverctx_opt(opt::max_streams ms);
    };

}  // namespace oxen::quic
