# cmake bits to do a full static build, downloading and building all dependencies.

# Most of these are CACHE STRINGs so that you can override them using -DWHATEVER during cmake
# invocation to override.

set(LOCAL_MIRROR "" CACHE STRING "local mirror path/URL for lib downloads")

set(LIBUNISTRING_VERSION 1.1 CACHE STRING "libunistring version")
set(LIBUNISTRING_MIRROR ${LOCAL_MIRROR} https://ftp.gnu.org/gnu/libunistring
    CACHE STRING "libunistring mirror(s)")
set(LIBUNISTRING_SOURCE libunistring-${LIBUNISTRING_VERSION}.tar.xz)
set(LIBUNISTRING_HASH SHA512=01a4267bbd301ea5c389b17ee918ae5b7d645da8b2c6c6f0f004ff2dead9f8e50cda2c6047358890a5fceadc8820ffc5154879193b9bb8970f3fb1fea1f411d6
    CACHE STRING "libunistring source hash")

set(LIBIDN2_VERSION 2.3.4 CACHE STRING "libidn2 version")
set(LIBIDN2_MIRROR ${LOCAL_MIRROR} https://ftp.gnu.org/gnu/libidn
    CACHE STRING "libidn2 mirror(s)")
set(LIBIDN2_SOURCE libidn2-${LIBIDN2_VERSION}.tar.gz)
set(LIBIDN2_HASH SHA512=a6e90ccef56cfd0b37e3333ab3594bb3cec7ca42a138ca8c4f4ce142da208fa792f6c78ca00c01001c2bc02831abcbaf1cf9bcc346a5290fd7b30708f5a462f3
    CACHE STRING "libidn2 source hash")

set(ZSTD_VERSION 1.5.5 CACHE STRING "zstd version")
set(ZSTD_MIRROR ${LOCAL_MIRROR} https://github.com/facebook/zstd/releases/download/${ZSTD_VERSION}
    CACHE STRING "zstd mirror(s)")
set(ZSTD_SOURCE zstd-${ZSTD_VERSION}.tar.gz)
set(ZSTD_HASH SHA512=99109ec0e07fa65c2101c9cb36be56b672bbd0ee69d265f924718e61f9192ae8385c8d9e4d0c318be9edfa6d849fd3d60e5f164fa120961449429ea3c5dab6b6
    CACHE STRING "zstd source hash")

set(GMP_VERSION 6.3.0 CACHE STRING "gmp version")
set(GMP_MIRROR ${LOCAL_MIRROR} https://gmplib.org/download/gmp
    CACHE STRING "gmp mirror(s)")
set(GMP_SOURCE gmp-${GMP_VERSION}.tar.xz)
set(GMP_HASH SHA512=e85a0dab5195889948a3462189f0e0598d331d3457612e2d3350799dba2e244316d256f8161df5219538eb003e4b5343f989aaa00f96321559063ed8c8f29fd2
    CACHE STRING "gmp source hash")

set(NETTLE_VERSION 3.9.1 CACHE STRING "nettle version")
set(NETTLE_MIRROR ${LOCAL_MIRROR} https://ftp.gnu.org/gnu/nettle
    CACHE STRING "nettle mirror(s)")
set(NETTLE_SOURCE nettle-${NETTLE_VERSION}.tar.gz)
set(NETTLE_HASH SHA512=5939c4b43cf9ff6c6272245b85f123c81f8f4e37089fa4f39a00a570016d837f6e706a33226e4bbfc531b02a55b2756ff312461225ed88de338a73069e031ced
    CACHE STRING "nettle source hash")

set(LIBTASN1_VERSION 4.19.0 CACHE STRING "libtasn1 version")
set(LIBTASN1_MIRROR ${LOCAL_MIRROR} https://ftp.gnu.org/gnu/libtasn1
    CACHE STRING "libtasn1 mirror(s)")
set(LIBTASN1_SOURCE libtasn1-${LIBTASN1_VERSION}.tar.gz)
set(LIBTASN1_HASH SHA512=287f5eddfb5e21762d9f14d11997e56b953b980b2b03a97ed4cd6d37909bda1ed7d2cdff9da5d270a21d863ab7e54be6b85c05f1075ac5d8f0198997cf335ef4
    CACHE STRING "libtasn1 source hash")

set(LIBEVENT_VERSION 2.1.12-stable CACHE STRING "libevent version")
set(LIBEVENT_MIRROR ${LOCAL_MIRROR} https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}
    CACHE STRING "libevent mirror(s)")
set(LIBEVENT_SOURCE libevent-${LIBEVENT_VERSION}.tar.gz)
set(LIBEVENT_HASH SHA512=88d8944cd75cbe78bc4e56a6741ca67c017a3686d5349100f1c74f8a68ac0b6410ce64dff160be4a4ba0696ee29540dfed59aaf3c9a02f0c164b00307fcfe84f
    CACHE STRING "libevent source hash")

set(cross_host "")
set(cross_rc "")
if(CMAKE_CROSSCOMPILING)
  set(cross_host "--host=${ARCH_TRIPLET}")
  if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
    set(cross_rc "WINDRES=${CMAKE_RC_COMPILER}")
  endif()
endif()
if(ANDROID)
  set(android_toolchain_suffix linux-android)
  set(android_compiler_suffix linux-android23)
  if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
    set(android_machine x86_64)
    set(cross_host "--host=x86_64-linux-android")
    set(android_compiler_prefix x86_64)
    set(android_compiler_suffix linux-android23)
    set(android_toolchain_prefix x86_64)
    set(android_toolchain_suffix linux-android)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES x86)
    set(android_machine x86)
    set(cross_host "--host=i686-linux-android")
    set(android_compiler_prefix i686)
    set(android_compiler_suffix linux-android23)
    set(android_toolchain_prefix i686)
    set(android_toolchain_suffix linux-android)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES armeabi-v7a)
    set(android_machine arm)
    set(cross_host "--host=armv7a-linux-androideabi")
    set(android_compiler_prefix armv7a)
    set(android_compiler_suffix linux-androideabi23)
    set(android_toolchain_prefix arm)
    set(android_toolchain_suffix linux-androideabi)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES arm64-v8a)
    set(android_machine arm64)
    set(cross_host "--host=aarch64-linux-android")
    set(android_compiler_prefix aarch64)
    set(android_compiler_suffix linux-android23)
    set(android_toolchain_prefix aarch64)
    set(android_toolchain_suffix linux-android)
  else()
    message(FATAL_ERROR "unknown android arch: ${CMAKE_ANDROID_ARCH_ABI}")
  endif()
  set(deps_cc "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/${android_compiler_prefix}-${android_compiler_suffix}-clang")
  set(deps_cxx "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/${android_compiler_prefix}-${android_compiler_suffix}-clang++")
  set(deps_ld "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/${android_compiler_prefix}-${android_toolchain_suffix}-ld")
  set(deps_ranlib "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/${android_toolchain_prefix}-${android_toolchain_suffix}-ranlib")
  set(deps_ar "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/${android_toolchain_prefix}-${android_toolchain_suffix}-ar")
endif()

set(deps_CFLAGS "-O2")
set(deps_CXXFLAGS "-O2")

if(WITH_LTO)
  set(deps_CFLAGS "${deps_CFLAGS} -flto")
endif()

if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
  set(deps_CFLAGS "${deps_CFLAGS} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  set(deps_CXXFLAGS "${deps_CXXFLAGS} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

if(_winver)
  set(deps_CFLAGS "${deps_CFLAGS} -D_WIN32_WINNT=${_winver}")
  set(deps_CXXFLAGS "${deps_CXXFLAGS} -D_WIN32_WINNT=${_winver}")
endif()

set(apple_cflags_arch)
set(apple_cxxflags_arch)
set(apple_ldflags_arch)
set(gmp_build_host "${cross_host}")
if(APPLE AND CMAKE_CROSSCOMPILING)
    if(gmp_build_host MATCHES "^(.*-.*-)ios([0-9.]+)(-.*)?$")
        set(gmp_build_host "${CMAKE_MATCH_1}darwin${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
    endif()
    if(gmp_build_host MATCHES "^(.*-.*-.*)-simulator$")
        set(gmp_build_host "${CMAKE_MATCH_1}")
    endif()

    set(apple_arch)
    if(ARCH_TRIPLET MATCHES "^(arm|aarch)64.*")
        set(apple_arch "arm64")
    elseif(ARCH_TRIPLET MATCHES "^x86_64.*")
        set(apple_arch "x86_64")
    else()
        message(FATAL_ERROR "Don't know how to specify -arch for GMP for ${ARCH_TRIPLET} (${APPLE_TARGET_TRIPLE})")
    endif()

    set(apple_cflags_arch " -arch ${apple_arch}")
    set(apple_cxxflags_arch " -arch ${apple_arch}")
    if(CMAKE_OSX_DEPLOYMENT_TARGET)
      if (SDK_NAME)
        set(apple_ldflags_arch " -m${SDK_NAME}-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
      elseif(CMAKE_OSX_DEPLOYMENT_TARGET)
        set(apple_ldflags_arch " -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
      endif()
    endif()
    set(apple_ldflags_arch "${apple_ldflags_arch} -arch ${apple_arch}")

    if(CMAKE_OSX_SYSROOT)
      foreach(f c cxx ld)
        set(apple_${f}flags_arch "${apple_${f}flags_arch} -isysroot ${CMAKE_OSX_SYSROOT}")
      endforeach()
    endif()
elseif(gmp_build_host STREQUAL "")
    set(gmp_build_host "--build=${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

build_external(libtasn1
    CONFIGURE_EXTRA --disable-doc
    BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/libtasn1.a ${DEPS_DESTDIR}/include/libtasn1.h)
add_static_target(libtasn1 libtasn1_external libtasn1.a)

build_external(libunistring
    BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/libunistring.a ${DEPS_DESTDIR}/include/unistr.h)
add_static_target(libunistring libunistring_external libunistring.a)

build_external(libidn2
    CONFIGURE_EXTRA --disable-doc
    DEPENDS libunistring_external
    BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/libidn2.a ${DEPS_DESTDIR}/include/idn2.h)
add_static_target(libidn2 libidn2_external libidn2.a libunistring)

build_external(gmp
    CONFIGURE_COMMAND ./configure ${gmp_build_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
        "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}${apple_cflags_arch}" "CXXFLAGS=${deps_CXXFLAGS}${apple_cxxflags_arch}"
        "LDFLAGS=${apple_ldflags_arch}" ${cross_rc} CC_FOR_BUILD=cc CPP_FOR_BUILD=cpp
    DEPENDS libidn2_external libtasn1_external
)
add_static_target(gmp gmp_external libgmp.a libidn2 libtasn1)

build_external(nettle
    CONFIGURE_COMMAND ./configure ${gmp_build_host} --disable-shared --prefix=${DEPS_DESTDIR} --libdir=${DEPS_DESTDIR}/lib
        --with-pic --disable-openssl
        "CC=${deps_cc}" "CXX=${deps_cxx}"
        "CFLAGS=${deps_CFLAGS}${apple_cflags_arch}" "CXXFLAGS=${deps_CXXFLAGS}${apple_cxxflags_arch}"
        "CPPFLAGS=-I${DEPS_DESTDIR}/include"
        "LDFLAGS=-L${DEPS_DESTDIR}/lib${apple_ldflags_arch}"

    DEPENDS gmp_external
    BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libnettle.a
    ${DEPS_DESTDIR}/lib/libhogweed.a
    ${DEPS_DESTDIR}/include/nettle/version.h
)
add_static_target(nettle nettle_external libnettle.a gmp)
add_static_target(hogweed nettle_external libhogweed.a nettle)

include(gnutls_source)

build_external(libevent
    CONFIGURE_EXTRA --disable-openssl
    BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libevent_core.a
    ${DEPS_DESTDIR}/lib/libevent_pthreads.a
    ${DEPS_DESTDIR}/include/event2/event.h
)
add_static_target(libevent::core libevent_external libevent_core.a)
if(WIN32)
    add_library(libevent::threads ALIAS libevent::core)
else()
    add_static_target(libevent::threads libevent_external libevent_pthreads.a)
endif()

