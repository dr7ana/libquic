#include <catch2/catch_test_macros.hpp>
#include <quic.hpp>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("001: Server-client handshaking", "[001][handshake]")
    {
        logger_config();

        log::debug(log_cat, "Beginning test of DTLS handshake...");

        Network test_net{};
        std::atomic<bool> good{false};
        std::atomic<int> data_check{0};
        auto msg = "hello from the other siiiii-iiiiide"_bsv;

		std::shared_ptr<Stream> server_extracted;

        gnutls_callback outbound_tls_cb = [&](gnutls_session_t session,
					unsigned int htype,
					unsigned int when,
					unsigned int incoming,
					const gnutls_datum_t* msg) {
            log::debug(log_cat, "Calling client TLS callback... handshake completed...");

            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& ep = static_cast<Connection*>(conn_ref->user_data)->endpoint();

            REQUIRE(ep != nullptr);

            good = true;
            return 0;
        };

		stream_data_callback_t server_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling server stream data callback... data received: {}", buffer_printer{dat});
            data_check += 1;
        };
		stream_data_callback_t client_data_cb = [&](Stream& s, bstring_view dat) {
            log::debug(log_cat, "Calling client stream data callback... data received: {}", buffer_printer{dat});
            data_check += 1;
        };

		stream_open_callback_t stream_open_cb = [&](Stream& s){
            log::debug(log_cat, "Calling server stream open callback... stream opened...");
			server_extracted = s.shared_from_this();
			return 0;
		};

        auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);

        auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);
		client_tls->client_tls_policy = std::move(outbound_tls_cb);

        opt::local_addr server_local{"127.0.0.1"s, 5500};
        opt::local_addr client_local{"127.0.0.1"s, 4400};
        opt::remote_addr client_remote{"127.0.0.1"s, 5500};

		auto server_endpoint = test_net.endpoint(server_local);
		bool sinit = server_endpoint->inbound_init(server_tls, server_data_cb, stream_open_cb);

		REQUIRE(sinit);

        auto client_endpoint = test_net.endpoint(client_local);

		auto conn_interface = client_endpoint->connect(client_remote, client_tls);

		std::this_thread::sleep_for(1s);

		// client make stream and send; message displayed by server_data_cb
		auto client_stream = conn_interface->get_new_stream(client_data_cb);
		client_stream->send(msg);

        std::this_thread::sleep_for(1s);

		// server send data using stream; message displayed by client_data_cb
		server_extracted->send(msg);

		std::this_thread::sleep_for(1s);

        REQUIRE(good);
		REQUIRE(data_check == 2);
        test_net.close();
    };
}  // namespace oxen::quic::test
