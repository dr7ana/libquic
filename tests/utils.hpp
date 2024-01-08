#pragma once

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <charconv>
#include <future>
#include <optional>
#include <oxen/log.hpp>
#include <quic/endpoint.hpp>
#include <quic/gnutls_crypto.hpp>
#include <quic/network.hpp>
#include <quic/utils.hpp>
#include <string>

#include "oxenc/base64.h"

namespace oxen::quic
{
    extern bool disable_ipv6, disable_rotating_buffer;

    inline auto test_cat = oxen::log::Cat("test");

    using namespace oxenc::literals;

    inline const std::string TEST_ENDPOINT = "test_endpoint"s;
    inline const std::string TEST_BODY = "test_body"s;

    namespace test::defaults
    {
        inline std::pair<std::string, std::string> CLIENT_KEYS, SERVER_KEYS;
        inline const std::string& CLIENT_SEED = CLIENT_KEYS.first;
        inline const std::string& CLIENT_PUBKEY = CLIENT_KEYS.second;
        inline const std::string& SERVER_SEED = SERVER_KEYS.first;
        inline const std::string& SERVER_PUBKEY = SERVER_KEYS.second;

        std::pair<std::shared_ptr<GNUTLSCreds>, std::shared_ptr<GNUTLSCreds>> tls_creds_from_ed_keys();
    }  // namespace test::defaults

    // Generates a random Ed25519 keypair for testing purposes.  Returned values are the 32-byte
    // seed and 32-byte pubkey.
    std::pair<std::string, std::string> generate_ed25519();

    // Takes a hex- or base64-encoded byte value of the given byte size and returns the bytes.
    // Returns nullopt if the encoded value is not a valid byte encoding of the given size.
    template <typename Char = char>
    inline std::optional<std::basic_string<Char>> decode_bytes(std::string_view encoded, size_t size = 32)
    {
        if (encoded.size() == size * 2 && oxenc::is_hex(encoded))
            return oxenc::from_hex<Char>(encoded);
        if (encoded.size() >= oxenc::to_base64_size(size, false) && encoded.size() <= oxenc::to_base64_size(32, true) &&
            oxenc::is_base64(encoded))
            return oxenc::from_base64<Char>(encoded);
        return std::nullopt;
    }

    void add_log_opts(CLI::App& cli, std::string& file, std::string& level);

    void setup_logging(std::string out, const std::string& level);

    /// RAII class that resets the log level for the given category while the object is alive, then
    /// resets it to what it was at construction when the object is destroyed.
    struct log_level_override
    {
        log::Level previous;
        log_level_override(log::Level l, std::string category = "quic") : previous{log::get_level(category)}
        {
            log::set_level(category, l);
        }
        ~log_level_override() { log::set_level("quic", previous); }
    };

    /// Same as above, but only raises the log level to a more serious cutoff (leaving it alone if
    /// already higher).
    struct log_level_raiser : log_level_override
    {
        log_level_raiser(log::Level l, std::string category = "quic") :
                log_level_override{std::max(l, log::get_level(category)), category}
        {}
    };
    /// Same as above, but only lowers the log level to a more frivolous cutoff (leaving it alone if
    /// already lower).
    struct log_level_lowerer : log_level_override
    {
        log_level_lowerer(log::Level l, std::string category = "quic") :
                log_level_override{std::min(l, log::get_level(category)), category}
        {}
    };

    /// Parses an integer of some sort from a string, requiring that the entire string be consumed
    /// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
    /// string was consumed.
    template <typename T>
    bool parse_int(const std::string_view str, T& value, int base = 10)
    {
        T tmp;
        auto* strend = str.data() + str.size();
        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
        if (ec != std::errc() || p != strend)
            return false;
        value = tmp;
        return true;
    }

    std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port = std::nullopt);

    template <typename F>
    auto require_future(F& f, std::chrono::milliseconds timeout = 1s)
    {
        REQUIRE(f.wait_for(timeout) == std::future_status::ready);
        return f.get();
    }

    template <typename T>
    struct functional_helper : public functional_helper<decltype(&T::operator())>
    {};

    template <typename Class, typename Ret, typename... Args>
    struct functional_helper<Ret (Class::*)(Args...) const>
    {
        using return_type = Ret;
        static constexpr bool is_void = std::is_void_v<Ret>;
        using type = std::function<Ret(Args...)>;
    };

    template <typename T>
    using functional_helper_t = typename functional_helper<T>::type;

    struct set_on_exit
    {
        std::promise<void>& p;
        explicit set_on_exit(std::promise<void>& p) : p{p} {}
        ~set_on_exit() { p.set_value(); }
    };

    /// Test suite helper that takes a callable lambda at construction and then man-in-the-middles
    /// an intermediate std::function matching the lambda that calls the inner lambda but also sets
    /// a promise just after calling the inner lambda.
    ///
    /// The main purpose is to synchronize an asynchronous interface with a promise/future to
    /// simplify test code which is full of "wait for this thing to be called" checks, without
    /// needing any sort of sleep & poll (and reducing the direct usage of promise/futures in the
    /// test suite).
    ///
    /// Usage example:
    ///
    ///     int foo = 0;
    ///     callback_waiter waiter{[&foo](int a, int b) { foo = a + b; }};
    ///     invoke_something(waiter);
    ///
    /// where `invoke_something` takes a `std::function<int(Foo&, int)>`.  The test code would then
    /// go on to synchronize with:
    ///
    ///     REQUIRE(waiter.wait(/* 1s */)); // will fail if the lambda doesn't get called within ~1s
    ///
    /// and then can go on to check side effects of the lambda, e.g.:
    ///
    ///     CHECK(foo == 42);
    ///
    /// Care must be taken to ensure the lambda is only called once.  The lambda may throw, but the
    /// throw propagates to the caller of the lambda, *not* the inner promise.
    template <typename T>
    struct callback_waiter
    {
        using Func_t = functional_helper_t<T>;

        Func_t func;
        std::promise<void> p;
        std::future<void> f{p.get_future()};

        explicit callback_waiter(T f) : func{std::move(f)} {}

        bool wait(std::chrono::milliseconds timeout = 1s) { return f.wait_for(timeout) == std::future_status::ready; }

        bool is_ready() { return wait(0s); }

        // Deliberate implicit conversion to the std::function<...>
        operator Func_t()
        {
            return [this](auto&&... args) {
                set_on_exit prom_setter{p};
                return func(std::forward<decltype(args)>(args)...);
            };
        }
    };

}  // namespace oxen::quic
