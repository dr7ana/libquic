#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <future>
#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

namespace oxen::quic::test
{
    constexpr int COOLDOWN_ITERATIONS{6};
    constexpr int TOTAL_ITERATIONS{10};
    constexpr auto COOLDOWN{3s};

    constexpr auto WAIT_A{
            COOLDOWN_ITERATIONS *
#ifdef __APPLE__
            1000ms
#else
            150ms
#endif
    };

    constexpr auto WAIT_B{WAIT_A + 2 * COOLDOWN};

    TEST_CASE("014 - Event Trigger", "[014][trigger]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"_bsv;

        std::promise<void> prom_a, prom_b;
        std::future<void> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        std::shared_ptr<Trigger> trigger = nullptr;

        stream_data_callback server_data_cb = [&](Stream&, bstring_view) {
            recv_counter += 1;
            if (recv_counter == COOLDOWN_ITERATIONS)
            {
                log::critical(log_cat, "Received {} messages!", COOLDOWN_ITERATIONS);
                prom_a.set_value();
            }
            if (recv_counter == TOTAL_ITERATIONS)
            {
                log::critical(log_cat, "Received {} messages!", TOTAL_ITERATIONS);
                prom_b.set_value();
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, "127.0.0.1"s, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        trigger = Trigger::make(
                test_net._loop,
                COOLDOWN,
                [&]() {
                    if (send_counter < TOTAL_ITERATIONS)
                    {
                        send_counter += 1;
                        client_stream->send(msg);
                    }

                    if (send_counter == TOTAL_ITERATIONS)
                    {
                        log::critical(log_cat, "Halting EventTrigger!");
                        trigger->halt();
                    }
                },
                COOLDOWN_ITERATIONS);

        require_future(fut_a, WAIT_A);

        CHECK(recv_counter == COOLDOWN_ITERATIONS);

        require_future(fut_b, WAIT_B);

        CHECK(recv_counter == TOTAL_ITERATIONS);
    }
}  //  namespace oxen::quic::test
