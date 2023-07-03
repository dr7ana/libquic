#pragma once

#include "format.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    // Holds an address, with a ngtcp2_addr held for easier passing into ngtcp2 functions
    struct Address
    {
      private:
        sockaddr_storage _sock_addr{};
        ngtcp2_addr _addr{reinterpret_cast<sockaddr*>(&_sock_addr), 0};

        void _copy_internals(const Address& obj)
        {
            std::memmove(&_sock_addr, &obj._sock_addr, sizeof(_sock_addr));
            _addr.addrlen = obj._addr.addrlen;
        }

      public:
        // Default constructor yields [::]:0
        Address()
        {
            _sock_addr.ss_family = AF_INET6;
            _addr.addrlen = sizeof(sockaddr_in6);
        }

        Address(const sockaddr* s, socklen_t n)
        {
            std::memmove(&_sock_addr, s, n);
            _addr.addrlen = n;
        }
        explicit Address(const sockaddr* s) :
                Address{s, static_cast<socklen_t>(s->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6))}
        {}
        explicit Address(const sockaddr_in* s) : Address{reinterpret_cast<const sockaddr*>(s), sizeof(sockaddr_in)} {}
        explicit Address(const sockaddr_in6* s) : Address{reinterpret_cast<const sockaddr*>(s), sizeof(sockaddr_in6)} {}
        Address(const std::string& addr, uint16_t port);

        // Assignment from a sockaddr pointer; we copy the sockaddr's contents
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr>,
                        int> = 0>
        Address& operator=(const T* s)
        {
            _addr.addrlen = std::is_same_v<T, sockaddr>
                                  ? s->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)
                                  : sizeof(T);
            std::memmove(&_sock_addr, s, _addr.addrlen);
            return *this;
        }

        Address(const Address& obj) { _copy_internals(obj); }
        Address& operator=(const Address& obj)
        {
            _copy_internals(obj);
            return *this;
        }

        inline bool is_ipv4() const
        {
            return _addr.addrlen == sizeof(sockaddr_in) &&
                   reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_family == AF_INET;
        }
        inline bool is_ipv6() const
        {
            return _addr.addrlen == sizeof(sockaddr_in6) &&
                   reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_family == AF_INET6;
        }

        // Accesses the sockaddr_in for this address.  Precondition: `is_ipv4()`
        inline const sockaddr_in& in4() const
        {
            assert(is_ipv4());
            return reinterpret_cast<const sockaddr_in&>(_sock_addr);
        }

        // Accesses the sockaddr_in6 for this address.  Precondition: `is_ipv6()`
        inline const sockaddr_in6& in6() const
        {
            assert(is_ipv6());
            return reinterpret_cast<const sockaddr_in6&>(_sock_addr);
        }

        inline uint16_t port() const
        {
            assert(is_ipv4() || is_ipv6());

            return oxenc::big_to_host(
                    is_ipv4() ? reinterpret_cast<const sockaddr_in&>(_sock_addr).sin_port
                              : reinterpret_cast<const sockaddr_in6&>(_sock_addr).sin6_port);
        }

        // template code to implicitly convert to sockaddr*, sockaddr_in*, sockaddr_in6* so that
        // this can be passed into C functions taking such a pointer (for the first you also want
        // `socklen()`).
        //
        // Because this is a deducated templated type, dangerous implicit conversions from the
        // pointer to other things (like bool) won't occur.
        //
        // If the given pointer is mutated you *must* call update_socklen() afterwards.
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr_in6>,
                        int> = 0>
        operator T*()
        {
            return reinterpret_cast<T*>(&_sock_addr);
        }
        template <
                typename T,
                std::enable_if_t<
                        std::is_same_v<T, sockaddr> || std::is_same_v<T, sockaddr_in> || std::is_same_v<T, sockaddr_in6>,
                        int> = 0>
        operator const T*() const
        {
            return reinterpret_cast<const T*>(&_sock_addr);
        }

        // Conversion to a const ngtcp2_addr reference and pointer.  We don't provide non-const
        // access because this points at our internal data.
        operator const ngtcp2_addr&() const { return _addr; }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_addr*>, int> = 0>
        operator const T*() const
        {
            return &_addr;
        }

        bool operator==(const Address& other) const
        {
            if (is_ipv4() && other.is_ipv4())
            {
                auto& a = in4();
                auto& b = other.in4();
                return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
            }
            if (is_ipv6() && other.is_ipv6())
            {
                auto& a = in6();
                auto& b = other.in6();
                return a.sin6_port == b.sin6_port &&
                       memcmp(a.sin6_addr.s6_addr, b.sin6_addr.s6_addr, sizeof(a.sin6_addr.s6_addr)) == 0;
            }
            return false;
        }

        // Returns the size of the sockaddr
        socklen_t socklen() const { return _addr.addrlen; }

        // Returns a pointer to the sockaddr size; typically you want this when updating the address
        // via a function like `getsockname`.
        socklen_t* socklen_ptr() { return &_addr.addrlen; }

        // Updates the socklen of the sockaddr; this must be called if directly modifying the
        // address via one of the sockaddr* pointer operators.  (It is not needed when assigning a
        // sockaddr pointer).
        void update_socklen(socklen_t len) { _addr.addrlen = len; }

        // Convenience method for debugging, etc.  This is usually called implicitly by passing the
        // Address to fmt to format it.
        std::string to_string() const;
    };
    template <>
    inline constexpr bool IsToStringFormattable<Address> = true;

    // Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    // to ngtcp2_path*
    struct Path
    {
      public:
        Address local;
        Address remote;

      private:
        ngtcp2_path _path{local, remote, nullptr};

      public:
        Path() = default;
        Path(const Address& l, const Address& r) : local{l}, remote{r} {}
        Path(const Path& p) : Path{p.local, p.remote} {}

        Path& operator=(const Path& p)
        {
            local = p.local;
            remote = p.remote;
            _path.local = local;
            _path.remote = remote;
            return *this;
        }

        // template code to pass Path as ngtcp2_path into ngtcp2 functions
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator T*()
        {
            return &_path;
        }
        template <typename T, std::enable_if_t<std::is_same_v<T, ngtcp2_path>, int> = 0>
        operator const T*() const
        {
            return &_path;
        }

        std::string to_string() const;
    };
    template <>
    inline constexpr bool IsToStringFormattable<Path> = true;
    
}   // namespace oxen::quic


namespace std
{
    inline constexpr size_t inverse_golden_ratio = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;
    
    template <>
    struct hash<oxen::quic::Address>
    {
        size_t operator()(const oxen::quic::Address& addr) const
        {
            std::string_view addr_data;
            in_port_t port;
            if (addr.is_ipv4())
            {
                auto& ip4 = addr.in4();
                addr_data = {reinterpret_cast<const char*>(&ip4.sin_addr.s_addr), sizeof(ip4.sin_addr.s_addr)};
                port = ip4.sin_port;
            }
            else
            {
                assert(addr.is_ipv6());
                auto& ip6 = addr.in6();
                addr_data = {reinterpret_cast<const char*>(ip6.sin6_addr.s6_addr), sizeof(ip6.sin6_addr.s6_addr)};
                port = ip6.sin6_port;
            }

            auto h = hash<string_view>{}(addr_data);
            h ^= hash<in_port_t>{}(port) + inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };
}   // namespace std
