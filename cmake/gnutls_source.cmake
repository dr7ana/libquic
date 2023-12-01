# Source version, download location, hash for gnutls
#
# This gets used both in:
#   1) the full StaticBuild code 
#   2) projects packaging libquic that require a static build only for gnutls

set(gnutls_build_extra "")
set(gnutls_link_extra "")

if (STATIC_BUILD_DEPS)
    set(gnutls_build_extra DEPENDS nettle_external)
endif()

if (FORCE_STATIC_GNUTLS)
    add_library(libunistring INTERFACE)

    pkg_check_modules(LIBIDN2 libidn2 REQUIRED IMPORTED_TARGET)
    pkg_check_modules(LIBTASN1 libtasn1 REQUIRED IMPORTED_TARGET)
    pkg_check_modules(GMP gmp IMPORTED_TARGET)

    if (NOT GMP_FOUND)
        add_library(gmp INTERFACE)
        target_link_libraries(gmp INTERFACE -lgmp)
        add_library(gmp::gmp ALIAS gmp)
    else()
        add_library(gmp::gmp ALIAS PkgConfig::GMP)
    endif()

    pkg_check_modules(HOGWEED hogweed REQUIRED IMPORTED_TARGET)
    pkg_check_modules(NETTLE nettle IMPORTED_TARGET)

    if (NOT NETTLE_FOUND)
        add_library(nettle INTERFACE)
        target_link_libraries(nettle INTERFACE -lnettle)
        add_library(nettle::nettle ALIAS nettle)
    else()
        add_library(nettle::nettle ALIAS PkgConfig::NETTLE)
    endif()

    target_link_libraries(libunistring INTERFACE -lunistring)
    
    set(gnutls_link_extra 
        libunistring 
        gmp::gmp
        PkgConfig::HOGWEED 
        PkgConfig::LIBTASN1
        PkgConfig::LIBIDN2
        nettle::nettle)
else()
    set(gnutls_link_extra hogweed)
endif()

set(GNUTLS_VERSION 3.8.2 CACHE STRING "gnutls version")
string(REGEX REPLACE "^([0-9]+\\.[0-9]+)\\.[0-9]+$" "\\1" gnutls_version_nopatch "${GNUTLS_VERSION}")
set(GNUTLS_MIRROR ${LOCAL_MIRROR} https://www.gnupg.org/ftp/gcrypt/gnutls/v${gnutls_version_nopatch}
    CACHE STRING "gnutls mirror(s)")
set(GNUTLS_SOURCE gnutls-${GNUTLS_VERSION}.tar.xz)
set(GNUTLS_HASH SHA512=b3aa6e0fa7272cfca0bb0d364fe5dc9ca70cfd41878631d57271ba0a597cf6020a55a19e97a2c02f13a253455b119d296cf6f701be2b4e6880ebeeb07c93ef38
    CACHE STRING "gnutls source hash")

build_external(gnutls
    CONFIGURE_EXTRA ${cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
        --without-p11-kit --disable-libdane --disable-cxx --without-tpm --without-tpm2 --disable-doc
        --without-zlib --without-brotli --without-zstd --without-libintl-prefix --disable-tests
        --disable-valgrind-tests --disable-full-test-suite
        "PKG_CONFIG_PATH=${DEPS_DESTDIR}/lib/pkgconfig" "PKG_CONFIG=pkg-config"
        "CPPFLAGS=-I${DEPS_DESTDIR}/include" "LDFLAGS=-L${DEPS_DESTDIR}/lib"
        "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}" ${cross_rc}
    ${gnutls_build_extra}
    BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libgnutls.a
    ${DEPS_DESTDIR}/include/gnutls/gnutls.h
)

add_static_target(gnutls::gnutls gnutls_external libgnutls.a ${gnutls_link_extra})

set(GNUTLS_FOUND ON CACHE BOOL "")
set(GNUTLS_INCLUDE_DIR ${DEPS_DESTDIR}/include CACHE PATH "")
set(GNUTLS_LIBRARY ${DEPS_DESTDIR}/lib/libgnutls.a CACHE FILEPATH "")
set(GNUTLS_LIBRARIES ${DEPS_DESTDIR}/lib/libgnutls.a CACHE FILEPATH "")
if(WIN32)
    target_link_libraries(gnutls::gnutls INTERFACE ws2_32 ncrypt crypt32 iphlpapi)
endif()
