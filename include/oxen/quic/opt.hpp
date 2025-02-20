#pragma once

#include <stdexcept>

#include "address.hpp"
#include "crypto.hpp"
#include "types.hpp"

namespace oxen::quic
{
    class Endpoint;
    class Stream;

    namespace opt
    {
        using namespace std::chrono_literals;

        struct max_streams
        {
            uint64_t stream_count{DEFAULT_MAX_BIDI_STREAMS};
            max_streams() = default;
            explicit max_streams(uint64_t s) : stream_count{s} {}
        };

        // supported ALPNs for outbound connections
        struct outbound_alpns
        {
            std::vector<ustring> alpns;
            explicit outbound_alpns(std::vector<ustring> alpns = {}) : alpns{std::move(alpns)} {}

            // Convenience wrapper that sets a single ALPN value from a regular string:
            explicit outbound_alpns(std::string_view alpn) : outbound_alpns{{ustring{to_usv(alpn)}}} {}
        };

        // supported ALPNs for inbound connections
        struct inbound_alpns
        {
            std::vector<ustring> alpns;
            explicit inbound_alpns(std::vector<ustring> alpns = {}) : alpns{std::move(alpns)} {}

            // Convenience wrapper that sets a single ALPN value from a regular string:
            explicit inbound_alpns(std::string_view alpn) : inbound_alpns{{ustring{to_usv(alpn)}}} {}
        };

        // Sets the inbound and outbound ALPNs simulatneous to the same value(s).  This is equivalent to
        // passing outbound_alpns and inbound_alps, separately, with the same vector argument.
        struct alpns
        {
            std::vector<ustring> inout_alpns;
            explicit alpns(std::vector<ustring> alpns = {}) : inout_alpns{std::move(alpns)} {}

            // Convenience wrapper that sets a single ALPN value from a regular string:
            explicit alpns(std::string_view alpn) : alpns{{ustring{to_usv(alpn)}}} {}
        };

        struct handshake_timeout
        {
            std::chrono::nanoseconds timeout;
            explicit handshake_timeout(std::chrono::nanoseconds ns = 0ns) : timeout{ns} {}
        };

        // If non-zero, this sets a keep-alive timer for outgoing PINGs on this connection so that a
        // functioning but idle connection can stay alive indefinitely without hitting the connection's
        // idle timeout.  Typically in designing a protocol you need only one side to send pings; the
        // responses to a ping keep the connection in the other direction alive.  This value should
        // typically be lower than the idle_timeout of both sides of the connection to be effective.
        //
        // If this option is not specified or is set to a duration of 0 then outgoing PINGs will not be
        // sent on the connection.
        struct keep_alive
        {
            std::chrono::milliseconds time{0ms};
            keep_alive() = default;
            explicit keep_alive(std::chrono::milliseconds val) : time{val} {}
        };

        // Can be used to override the default (30s) maximum idle timeout for a connection.  Note that
        // this is negotiated during connection establishment, and the lower value advertised by each
        // side will be used for the connection.  Can be 0 to disable idle timeout entirely, but such an
        // option has caveats for connections across unknown internet boxes (see comments in RFC 9000,
        // section 10.1.2).
        struct idle_timeout
        {
            std::chrono::milliseconds timeout{DEFAULT_IDLE_TIMEOUT};
            idle_timeout() = default;
            explicit idle_timeout(std::chrono::milliseconds val) : timeout{val} {}
        };

        /// This can be initialized a few different ways. Simply passing a default constructed struct
        /// to Network::Endpoint(...) will enable datagrams without packet-splitting. From there, pass
        /// `Splitting::ACTIVE` to the constructor to enable packet-splitting.
        ///
        /// The size of the rotating datagram buffer can also be specified as a second parameter to the
        /// constructor. Buffer size is subdivided amongst 4 equally sized buffer rows, so the bufsize
        /// must be perfectly divisible by 4
        ///
        /// The max size of a transmittable datagram can be queried directly from connection_interface::
        /// get_max_datagram_size(). At connection initialization, ngtcp2 will default this value to 1200.
        /// The actual value is negotiated upwards via path discovery, reaching a theoretical maximum of
        /// NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE (1452), or near it, per datagram. Please note that enabling
        /// datagram splitting will double whatever value is returned.
        ///
        /// Note: this setting CANNOT be changed for an endpoint after creation, it must be
        /// destroyed and re-initialized with the desired settings.
        struct enable_datagrams
        {
            bool split_packets{false};
            Splitting mode{Splitting::NONE};
            // Note: this is the size of the entire buffer, divided amongst 4 rows
            int bufsize{4096};

            enable_datagrams() = default;
            explicit enable_datagrams(bool e) = delete;
            explicit enable_datagrams(Splitting m) : split_packets{true}, mode{m} {}
            explicit enable_datagrams(Splitting m, int b) : split_packets{true}, mode{m}, bufsize{b}
            {
                if (b <= 0)
                    throw std::out_of_range{"Bufsize must be positive"};
                if (b > 1 << 14)
                    throw std::out_of_range{"Bufsize too large"};
                if (b % 4 != 0)
                    throw std::invalid_argument{"Bufsize must be evenly divisible between 4 rows"};
            }
        };

        // Used to provide precalculated static secret data for an endpoint to use for validation
        // tokens.  If not provided, 32 random bytes are generated during endpoint construction.  The
        // data provided must be (at least) SECRET_MIN_SIZE long (longer values are ignored).  For a
        // deterministic value you should not pass sensitive data here (such as a raw private key), but
        // instead use a cryptographically secure hash (ideally with a unique key or suffix) of such
        // data.
        struct static_secret
        {
            inline static constexpr size_t SECRET_MIN_SIZE = 16;

            ustring secret;
            explicit static_secret(ustring s) : secret{std::move(s)}
            {
                if (secret.size() < SECRET_MIN_SIZE)
                    throw std::invalid_argument{
                            "opt::static_secret requires data of at least " + std::to_string(SECRET_MIN_SIZE) + "bytes"};
            }
        };

        // Used to provide a callback that bypasses sending packets out through the UDP socket. The passing of
        // this opt will also bypass the creation of the UDP socket entirely. The application will also need to
        // take responsibility for passing packets into the Endpoint via Endpoint::manually_receive_packet(...)
        struct manual_routing
        {
            using send_handler_t = std::function<void(const Path&, bstring_view)>;

          private:
            friend Endpoint;

            manual_routing() = default;

            send_handler_t send_hook = nullptr;

          public:
            explicit manual_routing(send_handler_t cb) : send_hook{std::move(cb)}
            {
                if (not send_hook)
                    throw std::runtime_error{"opt::manual_routing must be constructed with a send handler hook!"};
            }

            io_result operator()(const Path& p, bstring_view data, size_t& n)
            {
                send_hook(p, data);
                n = 0;
                return io_result{};
            }

            explicit operator bool() const { return send_hook != nullptr; }
        };

        // Used to provide callbacks for stream buffer watermarking. Application can pass an optional second parameter to
        // indicate that the logic should be executed once before the callback is cleared. The default behavior is for the
        // callback to persist and execute repeatedly
        struct watermark
        {
            using buffer_hook_t = std::function<void(Stream&)>;

          private:
            buffer_hook_t _hook = nullptr;
            bool _persist = true;

          public:
            watermark() = default;
            explicit watermark(buffer_hook_t hook, bool persist = true) : _hook{std::move(hook)}, _persist{persist} {}

            bool persist() const { return _persist; }

            void clear() { _hook = nullptr; }

            explicit operator bool() const { return _hook != nullptr; }

            void operator()(Stream& s)
            {
                _hook(s);

                if (not _persist)
                    _hook = nullptr;
            }
        };
    }  //  namespace opt
}  // namespace oxen::quic
