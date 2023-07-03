/*
    Test server binary
*/

#include <gnutls/gnutls.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>
#include <future>
#include <quic.hpp>
#include <quic/gnutls_crypto.hpp>
#include <thread>

#include "utils.hpp"

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test server"};

    std::string server_addr = "127.0.0.1:5500";

    cli.add_option("--listen", server_addr, "Server address to listen on")->type_name("IP:PORT")->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string key{"./serverkey.pem"}, cert{"./servercert.pem"};

    cli.add_option("-c,--certificate", cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-k,--key", key, "Path to server key to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    // TODO: make this optional
    std::string client_cert{"./clientcert.pem"};
    cli.add_option("-C,--clientcert", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    bool no_hash = false;
    cli.add_flag(
            "-H,--no-hash",
            no_hash,
            "Disable data hashing (just use a simple xor byte checksum instead).  Can make a difference on extremely low "
            "latency (e.g. localhost) connections.  Should be specified on the client as well.");
    bool no_checksum = false;
    cli.add_flag(
            "-X,--no-checksum",
            no_checksum,
            "Disable even the simple xor byte checksum (typically used together with -H).  Should be specified on the "
            "client as well.");

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network server_net{};

    auto server_tls = GNUTLSCreds::make(key, cert, client_cert);

    auto [listen_addr, listen_port] = parse_addr(server_addr, 5500);
    opt::local_addr server_local{listen_addr, listen_port};

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id);
        return 0;
    };

    struct stream_info
    {
        explicit stream_info(uint64_t expected) : expected{expected} { gnutls_hash_init(&hasher, GNUTLS_DIG_SHA3_256); }

        uint64_t expected;
        uint64_t received = 0;
        unsigned char checksum = 0;
        gnutls_hash_hd_t hasher;

        ~stream_info() { gnutls_hash_deinit(hasher, nullptr); }
    };

    std::unordered_map<ConnectionID, std::map<int64_t, stream_info>> csd;

    stream_data_callback stream_data = [&](Stream& s, bstring_view data) {
        auto& sd = csd[s.conn.scid()];
        auto it = sd.find(s.stream_id);
        if (it == sd.end())
        {
            if (data.size() < sizeof(uint64_t))
            {
                log::critical(test_cat, "Well this was unexpected: I got {} < 8 bytes", data.size());
                return;
            }
            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            data.remove_prefix(sizeof(uint64_t));
            it = sd.emplace(s.stream_id, size).first;
            log::warning(test_cat, "First data from new stream {}, expecting {}B!", s.stream_id, size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;
        info.received += data.size();
        if (info.received > info.expected)
        {
            log::critical(test_cat, "Received too much data ({}B > {}B)!");
            if (!need_more)
                return;
            data.remove_suffix(info.received - info.expected);
        }

        if (!no_checksum)
        {
            uint64_t csum = 0;
            const uint64_t* stuff = reinterpret_cast<const uint64_t*>(data.data());
            for (size_t i = 0; i < data.size() / 8; i++)
                csum ^= stuff[i];
            for (int i = 0; i < 8; i++)
                info.checksum ^= reinterpret_cast<const uint8_t*>(&csum)[i];
            for (size_t i = (data.size() / 8) * 8; i < data.size(); i++)
                info.checksum ^= static_cast<uint8_t>(data[i]);
        }

        if (!no_hash)
            gnutls_hash(info.hasher, reinterpret_cast<const unsigned char*>(data.data()), data.size());

        if (info.received >= info.expected)
        {
            std::basic_string<unsigned char> final_hash;
            final_hash.resize(33);
            gnutls_hash_output(info.hasher, final_hash.data());
            final_hash[32] = info.checksum;

            log::warning(
                    test_cat,
                    "Data from stream {} complete ({} B).  Final hash: {}",
                    s.stream_id,
                    info.received,
                    oxenc::to_hex(final_hash.begin(), final_hash.end()));

            s.send(std::move(final_hash));
        }
    };

    log::debug(test_cat, "Calling 'server_listen'...");
    auto _server = server_net.endpoint(server_local);
    _server->listen(server_tls, stream_opened, stream_data);

    for (;;)
        std::this_thread::sleep_for(10min);
}
