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
        std::shared_ptr<Endpoint> _endpoint;
        config_t config{};
		std::shared_ptr<TLSContext> tls_ctx;
        // std::shared_ptr<uv_udp_t> udp_handle;	// udp handle is 1:1 with endpoint
        session_tls_callback_t session_tls_cb;
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
		void handle_session_opt(opt::local_addr addr);
        void handle_session_opt(opt::remote_addr addr);
        void handle_session_opt(opt::client_tls tls);
        void handle_session_opt(session_tls_callback_t func);
        void handle_session_opt(opt::max_streams ms);
        void handle_session_opt(stream_data_callback_t func);
        void handle_session_opt(stream_open_callback_t func);
    };

}  // namespace oxen::quic
