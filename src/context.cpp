#include "context.hpp"

#include "connection.hpp"

namespace oxen::quic
{
    void SessionBase::handle_session_opt(opt::local_addr addr)
    {
        local = std::move(addr);
        log::trace(log_cat, "Endpoint stored local address: {}", local);
    }

    void SessionBase::handle_session_opt(opt::remote_addr addr)
    {
        remote = std::move(addr);
        log::trace(log_cat, "Endpoint stored remote address: {}", remote);
    }

    void SessionBase::handle_session_opt(opt::client_tls tls)
    {
        tls_ctx = std::move(tls).into_context();
    }

    void SessionBase::handle_session_opt(session_tls_callback_t func)
    {
        log::trace(log_cat, "Endpoint given TLS certification callback");
        auto ctx = std::dynamic_pointer_cast<GNUTLSContext>(tls_ctx);

        if (func)
        {
            ctx->session_tls_cb = std::move(func);
            ctx->client_callback_init();
        }
    }

    void SessionBase::handle_session_opt(opt::max_streams ms)
    {
        config.max_streams = ms.stream_count;
        log::trace(log_cat, "User passed max_streams_bidi config value: {}", config.max_streams);
    }

    void SessionBase::handle_session_opt(stream_data_callback_t func)
    {
        log::trace(log_cat, "Client given stream data callback");
        stream_data_cb = std::move(func);
    }

    void SessionBase::handle_session_opt(stream_open_callback_t func)
    {
        log::trace(log_cat, "Client given stream open callback");
        stream_open_cb = std::move(func);
    }

}  // namespace oxen::quic
