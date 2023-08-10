#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][execute]")
    {
        Network test_net{};
        auto good_msg = "hello from the other siiiii-iiiiide"_bsv;
        bstring_view bad_msg;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received...");
            REQUIRE(good_msg == dat);
            d_promise.set_value(true);
        };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls, server_data_cb));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->get_new_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg));
        REQUIRE_THROWS(client_stream->send(bad_msg));

        REQUIRE(d_future.get());
    };

    TEST_CASE("002 - Simple client to server transmission using ZMQ Bridge", "[002][zmq]")
    {
#ifdef NDEBUG
        SKIP("ZMQ unit tests require debug build");
#endif

#ifdef LIBQUIC_ZMQ_BRIDGE
        Network test_net{};

        std::promise<bool> tls;
        std::future<bool> tls_future = tls.get_future();

        gnutls_callback outbound_tls_cb =
                [&](gnutls_session_t, unsigned int, unsigned int, unsigned int, const gnutls_datum_t*) {
                    log::debug(log_cat, "Calling client TLS callback... handshake completed...");

                    tls.set_value(true);
                    return 0;
                };

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
        client_tls->set_client_tls_policy(outbound_tls_cb);

        opt::local_addr server_local{};
        opt::local_addr client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE(server_endpoint->listen(server_tls));

        opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(tls_future.get());
#else
        SKIP("ZMQ unit tests require `-DENABLE_ZMQ_BRIDGE` compilation flag");
#endif
    };

}  // namespace oxen::quic::test
