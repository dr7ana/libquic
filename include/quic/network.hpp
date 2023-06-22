#pragma once

extern "C"
{
#include <gnutls/gnutls.h>
}

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>
#include <uvw.hpp>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

using oxen::log::slns::source_location;

namespace oxen::quic
{
    template <typename... T>
    void loop_trace_log(
            const log::logger_ptr& cat_logger,
            [[maybe_unused]] const source_location& location,
            [[maybe_unused]] fmt::format_string<T...> fmt,
            [[maybe_unused]] T&&... args)
    {
#if defined(NDEBUG) && !defined(OXEN_LOGGING_RELEASE_TRACE)
        // Using [[maybe_unused]] on the *first* ctor argument breaks gcc 8/9
        (void)cat_logger;
#else
        if (cat_logger)
            cat_logger->log(log::detail::spdlog_sloc(location), log::Level::trace, fmt, std::forward<T>(args)...);
#endif
    }

	class Endpoint;

    class Network
    {
        using Job = std::pair<std::function<void()>, source_location>;
        using handle_address_pair = std::pair<const Address, std::shared_ptr<uv_udp_t>>;

      public:

        Network(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id thread_id);
        Network();
        ~Network();

<<<<<<< HEAD
        std::shared_ptr<Endpoint> endpoint(const Address& local_addr);
=======
        std::shared_ptr<uvw::loop> ev_loop;
        std::unique_ptr<std::thread> loop_thread;

        // Main client endpoint creation function. If a local address is passed, then a dedicated
        // uv_udt_t is bound to that address. To use this function four parameter structs can be
        // passed:
        //
        //      local_addr                          OPTIONAL (if not, the "any" address will be used)
        //      {
        //          std::string host,
        //          uint16_t port
        //      }
        //      or local_addr{uint16_t port} for any address with the given port.
        //
        //      remote_addr                         REQUIRED
        //      {
        //          std::string host,
        //          std::string port
        //      }
        //      client_tls                          REQUIRED
        //      {
        //          std::string client_key,         OPTIONAL (required if using client certificate
        //          std::string client_cert             authentication by server)
        //
        //          std::string server_cert         (A) REQUIRED (pick ***one*** of options A/B/C)
        //          std::string server_CA           (B)
        //      }
        //      client_tls_callback_t client_tls_cb (C)
        //
        template <typename... Opt>
        std::shared_ptr<Client> client_connect(Opt&&... opts)
        {
            std::promise<std::shared_ptr<Client>> p;
            auto f = p.get_future();
            quic_manager->call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize client context and client tls context simultaneously
                    std::shared_ptr<ClientContext> client_ctx =
                            std::make_shared<ClientContext>(quic_manager, std::forward<Opt>(opts)...);

                    client_ctx->udp_handle = handle_mapping(false, client_ctx->local);

                    // ensure addresses stored correctly
                    log::trace(log_cat, "Client local addr: {}", client_ctx->local);
                    log::trace(log_cat, "Client remote addr: {}", client_ctx->remote);

                    // create client and then copy assign it to the client context so we can return
                    // the shared ptr from this function
                    auto client_ptr = std::make_shared<Client>(
                            quic_manager, client_ctx, (*client_ctx).conn_id, client_ctx->udp_handle);
                    client_ctx->client = client_ptr;

                    quic_manager->clients.emplace_back(std::move(client_ctx));
                    log::trace(log_cat, "Client context emplaced");

                    p.set_value(client_ptr);
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }

        // Main server endpoint creation function. Binds a dedicated uv_udt_t to the binding
        // address passed. To use this function, two parameter structs can be passed:
        //
        //      local_addr                              REQUIRED
        //      {
        //          std::string host,
        //          uint16_t port
        //      } or local_addr{uint16_t port} for all addresses with a given port.
        //
        //      server_tls                              REQUIRED
        //      {
        //          std::string server_key,             REQUIRED
        //          std::string server_cert,            REQUIRED
        //          std::string client_ca_cert,         OPTIONAL (do not pass this and
        //          server_tls_cb)
        //      }
        //      server_tls_callback_t server_tls_cb     OPTIONAL (do not pass this and
        //      client_ca_cert)
        //
        // If a client CA cert is passed, it will be used as the CA authority for the connections;
        // if a server callback is passed, then the user is expected to implement logic that will
        // handle certificate verification during GNUTLS' handshake; if nothing is passed, no client
        // verification will be implemented.
        //
        template <typename... Opt>
        std::shared_ptr<Server> server_listen(Opt&&... opts)
        {
            std::promise<std::shared_ptr<Server>> p;
            auto f = p.get_future();
            quic_manager->call([&opts..., &p, this]() mutable {
                try
                {
                    // initialize server context and server tls context simultaneously
                    std::shared_ptr<ServerContext> server_ctx =
                            std::make_shared<ServerContext>(quic_manager, std::forward<Opt>(opts)...);

                    // ensure address stored correctly
                    log::trace(log_cat, "Server local addr: {}", server_ctx->local);

                    auto& [udp, tls] = server_ctx->udp_handles[server_ctx->local];
                    if (udp)
                        throw std::runtime_error{
                                "Unable to start server: we already have a server listening on that address"};

                    // UDP mapping
                    udp = handle_mapping(true, server_ctx->local);
                    tls = server_ctx->tls_creds;

                    // make server
                    server_ctx->server = std::make_shared<Server>(quic_manager, server_ctx);
                    auto server_ptr = server_ctx->server;

                    // emplace server context in handler set
                    quic_manager->servers.emplace(server_ctx->local, server_ctx);
                    // quic_manager->servers[server_ctx->local] = server_ctx;
                    log::trace(log_cat, "Server context emplaced");
                    p.set_value(server_ptr);
                }
                catch (...)
                {
                    p.set_exception(std::current_exception());
                }
            });

            return f.get();
        }
>>>>>>> 94c2b33 (Refactor TLS credential and session handling)

        void close();

		// Find and return the endpoint with the given local address; returns nullptr if not found
		Endpoint* get_endpoint(const Address& local);

      private:
        std::atomic<bool> running{false};
        std::shared_ptr<uvw::loop> ev_loop;
        std::unique_ptr<std::thread> loop_thread;

        // Maps local listening address to respective endpoint
        std::map<Address, std::shared_ptr<Endpoint>> endpoint_map;
        std::map<Address, std::shared_ptr<uv_udp_t>> handle_map;

        std::shared_ptr<uv_udp_t> map_udp_handle(const Address& local);

        std::shared_ptr<uv_udp_t> start_udp_handle(uv_loop_t* loop, const Address& bind);

        std::thread::id loop_thread_id;
        std::shared_ptr<uvw::async_handle> job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

      protected:
        friend class Endpoint;
        friend class Connection;
		friend class Stream;

        std::shared_ptr<uvw::loop> loop();

        bool in_event_loop() const;

        void call_soon(std::function<void(void)> f, source_location src = source_location::current());

        template <typename Callable>
        void call(Callable&& f, source_location src = source_location::current())
        {
            if (in_event_loop())
            {
                loop_trace_log(log_cat, src, "Event loop calling `{}`", src.function_name());
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f), std::move(src));
            }
        }

        void process_job_queue();

        void close_all();
    };

	static std::shared_ptr<Network> network_init();
	static std::shared_ptr<Network> network_init(std::shared_ptr<uvw::loop> loop_ptr, std::thread::id thread_id);

}  // namespace oxen::quic
