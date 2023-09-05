#include "gnutls_crypto.hpp"

extern "C"
{
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
}

#include <stdexcept>

#include <oxenc/hex.h>
#include <oxenc/base64.h>

#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"

namespace oxen::quic
{
    extern "C"
    {
        int gnutls_callback_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            const auto* conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto* conn = static_cast<Connection*>(conn_ref->user_data);
            const GNUTLSSession* tls_session = dynamic_cast<const GNUTLSSession*>(conn->get_session());
            assert(tls_session);

            return tls_session->do_tls_callback(session, htype, when, incoming, msg);
        }
    }

    GNUTLSCreds::GNUTLSCreds(std::string local_key, std::string local_cert, std::string remote_cert, std::string ca_arg)
    {
        if (local_key.empty() || local_cert.empty())
            throw std::runtime_error{
                    "Must initialize GNUTLS credentials using local private key and certificate at minimum"};

        datum lkey = datum{local_key};
        datum lcert = datum{local_cert};
        datum rcert;
        if (not remote_cert.empty())
            rcert = datum{remote_cert};
        datum ca;
        if (not ca_arg.empty())
            ca = datum{ca};

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        if (ca)
        {
            if (auto rv = (ca.from_mem)
                                ? gnutls_certificate_set_x509_trust_mem(cred, ca, ca.format)
                                : gnutls_certificate_set_x509_trust_file(cred, ca.path.u8string().c_str(), ca.format);
                rv < 0)
            {
                log::warning(log_cat, "Set x509 trust failed with code {}", gnutls_strerror(rv));
                throw std::invalid_argument("gnutls didn't like a specified trust file/memblock");
            }
        }

        if (auto rv = (lcert.from_mem)
                            ? gnutls_certificate_set_x509_key_mem(cred, lcert, lkey, lkey.format)
                            : gnutls_certificate_set_x509_key_file(
                                      cred, lcert.path.u8string().c_str(), lkey.path.u8string().c_str(), lkey.format);
            rv < 0)
        {
            log::warning(log_cat, "Set x509 key failed with code {}", gnutls_strerror(rv));
            throw std::invalid_argument("gnutls didn't like a specified key file/memblock");
        }

        log::info(log_cat, "Completed credential initialization");
    }

    GNUTLSCreds::GNUTLSCreds(std::string ed_seed, std::string ed_pubkey)
    {
        log::trace(log_cat, "Initializing GNUTLSCreds from Ed25519 keypair");

        // These bytes mean "this is a raw Ed25519 private key" in ASN.1 (or something like that)
        auto asn_seed_bytes = oxenc::from_hex("302e020100300506032b657004220420");
        asn_seed_bytes += ed_seed;

        std::string seed_pem = "-----BEGIN PRIVATE KEY-----\n";
        seed_pem += oxenc::to_base64(asn_seed_bytes);
        seed_pem += "\n-----END PRIVATE KEY-----\n";

        // These bytes mean "this is a raw Ed25519 public key" in ASN.1 (or something like that)
        auto asn_pubkey_bytes = oxenc::from_hex("302a300506032b6570032100");
        asn_pubkey_bytes += ed_pubkey;

        std::string pubkey_pem = "-----BEGIN PUBLIC KEY-----\n";
        pubkey_pem += oxenc::to_base64(asn_pubkey_bytes);
        pubkey_pem += "\n-----END PUBLIC KEY-----\n";

        //FIXME TODO XXX: debug printing of keys, delete this
        log::warning(log_cat, "Ed seed hex: {}\n", oxenc::to_hex(ed_seed));
        log::warning(log_cat, "\nEd seed PEM:\n{}\n", seed_pem);
        log::warning(log_cat, "Ed pubkey hex: {}\n", oxenc::to_hex(ed_pubkey));
        log::warning(log_cat, "\nEd pubkey PEM:\n{}\n", pubkey_pem);

        // uint32_t cast to appease narrowing conversion gods
        const gnutls_datum_t seed_datum{(uint8_t*)seed_pem.c_str(), (uint32_t)seed_pem.size()};
        const gnutls_datum_t pubkey_datum{(uint8_t*)pubkey_pem.c_str(), (uint32_t)pubkey_pem.size()};

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls credential allocation failed");
        }

        //FIXME: the key usage parameter (6th) is weird.  Since we only have the one keypair and
        //       we're only using it for ECDH, setting it to "use key for anything" should be fine.
        //       I believe the value for this is 0, and if it works it works.
        if (auto rv = gnutls_certificate_set_rawpk_key_mem(cred, &pubkey_datum, &seed_datum, GNUTLS_X509_FMT_PEM, nullptr, 0, nullptr, 0, 0); rv < 0)
        {
            log::warning(log_cat, "gnutls import of raw Ed keys failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls import of raw Ed keys failed");
        }
    }

    GNUTLSCreds::~GNUTLSCreds()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_certificate_free_credentials(cred);
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make(
            std::string remote_key, std::string remote_cert, std::string local_cert, std::string ca)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(remote_key, remote_cert, local_cert, ca)};
        return p;
    }

    std::shared_ptr<GNUTLSCreds> GNUTLSCreds::make_from_ed_keys(std::string seed, std::string pubkey)
    {
        // would use make_shared, but I want GNUTLSCreds' constructor to be private
        std::shared_ptr<GNUTLSCreds> p{new GNUTLSCreds(seed, pubkey)};
        return p;
    }

    std::unique_ptr<TLSSession> GNUTLSCreds::make_session(bool is_client)
    {
        return std::make_unique<GNUTLSSession>(*this, is_client);
    }

    void GNUTLSCreds::set_client_tls_policy(
            gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        client_tls_policy.f = std::move(func);
        client_tls_policy.htype = htype;
        client_tls_policy.when = when;
        client_tls_policy.incoming = incoming;
    }

    void GNUTLSCreds::set_server_tls_policy(
            gnutls_callback func, unsigned int htype, unsigned int when, unsigned int incoming)
    {
        server_tls_policy.f = std::move(func);
        server_tls_policy.htype = htype;
        server_tls_policy.when = when;
        server_tls_policy.incoming = incoming;
    }

    GNUTLSSession::~GNUTLSSession()
    {
        log::info(log_cat, "Entered {}", __PRETTY_FUNCTION__);
        gnutls_deinit(session);
    }

    void GNUTLSSession::set_tls_hook_functions()
    {
        log::debug(log_cat, "{} called", __PRETTY_FUNCTION__);
        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, gnutls_callback_wrapper);
    }

    GNUTLSSession::GNUTLSSession(GNUTLSCreds& creds, bool is_client) : creds{creds}, is_client{is_client}
    {
        log::trace(log_cat, "Entered {}", __PRETTY_FUNCTION__);

        log::trace(log_cat, "Creating {} GNUTLSSession", (is_client) ? "client" : "server");

        //TODO: needs GNUTLS_ENABLE_RAWPK flag if creds created with raw keys
        if (auto rv = gnutls_init(&session, is_client ? GNUTLS_CLIENT : GNUTLS_SERVER); rv < 0)
        {
            auto s = (is_client) ? "Client"s : "Server"s;
            log::warning(log_cat, "{} gnutls_init failed: {}", s, gnutls_strerror(rv));
            throw std::runtime_error("{} gnutls_init failed"_format(s));
        }

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
        {
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_set_default_priority failed");
        }

        if (is_client)
        {
            log::trace(log_cat, "gnutls configuring client session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }
        else
        {
            log::trace(log_cat, "gnutls configuring server session...");
            if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            {
                log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));
                throw std::runtime_error("ngtcp2_crypto_gnutls_configure_client_session failed");
            }
        }

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds.cred); rv < 0)
        {
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));
            throw std::runtime_error("gnutls_credentials_set failed");
        }

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (is_client)
        {
            if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            {
                log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));
                throw std::runtime_error("gnutls_server_name_set failed");
            }
        }

        set_tls_hook_functions();
    }

    int GNUTLSSession::do_tls_callback(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        auto& policy = (is_client) ? creds.client_tls_policy : creds.server_tls_policy;

        if (policy)
        {
            if (policy.htype == htype && policy.when == when && policy.incoming == incoming)
            {
                log::debug(log_cat, "Calling {} tls policy cb", (is_client) ? "client" : "server");
                return policy(session, htype, when, incoming, msg);
            }
        }
        return 0;
    }

}  // namespace oxen::quic
