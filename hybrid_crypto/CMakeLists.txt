cmake_minimum_required(VERSION 3.16)
project(hybrid_crypto C)

option(HYBRID_USE_GMSSL "Use GmSSL instead of OpenSSL 3 for SM2/SM3/SM4" OFF)
option(HYBRID_BUILD_APPS "Build demo server/client apps" ON)
option(HYBRID_BUILD_TESTS "Build unit tests" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Suppress OpenSSL 3 deprecated warnings to keep build clean while maintaining functionality
add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED=1)
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wno-deprecated-declarations)
endif()

# OpenSSL or GmSSL setup
if (HYBRID_USE_GMSSL)
  set(GMSSL_ROOT "/opt/gmssl" CACHE PATH "GmSSL install prefix")
  set(OPENSSL_INCLUDE_DIR "${GMSSL_ROOT}/include")
  set(OPENSSL_CRYPTO_LIBRARY "${GMSSL_ROOT}/lib/libcrypto.a")
  set(OPENSSL_SSL_LIBRARY "${GMSSL_ROOT}/lib/libssl.a")
  if (NOT EXISTS ${OPENSSL_CRYPTO_LIBRARY})
    message(FATAL_ERROR "GmSSL libcrypto not found at ${OPENSSL_CRYPTO_LIBRARY}")
  endif()
  if (NOT EXISTS ${OPENSSL_SSL_LIBRARY})
    message(FATAL_ERROR "GmSSL libssl not found at ${OPENSSL_SSL_LIBRARY}")
  endif()
  add_compile_definitions(USE_GMSSL=1)
  include_directories(${OPENSSL_INCLUDE_DIR})
else()
  find_package(OpenSSL REQUIRED)
  if (NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
  endif()
  include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# liboqs (prefer pkg-config, fallback to direct hints)
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
  pkg_check_modules(LIBOQS QUIET liboqs)
endif()

if (LIBOQS_FOUND)
  message(STATUS "Found liboqs via pkg-config: ${LIBOQS_VERSION}")
  include_directories(${LIBOQS_INCLUDE_DIRS})
  link_directories(${LIBOQS_LIBRARY_DIRS})
else()
  message(STATUS "pkg-config did not find liboqs, trying manual hints")
  find_library(OQS_LIBRARY NAMES oqs HINTS /usr/local/lib64 /usr/local/lib)
  find_path(OQS_INCLUDE_DIR oqs/oqs.h HINTS /usr/local/include)
  if (NOT OQS_LIBRARY OR NOT OQS_INCLUDE_DIR)
    message(FATAL_ERROR "liboqs not found. Ensure liboqs is installed. You may export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig and re-run cmake.")
  endif()
  include_directories(${OQS_INCLUDE_DIR})
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(hybrid_crypto STATIC
  src/hybrid_common.c
  src/hybrid_kex.c
  src/hybrid_sig.c
)

if (HYBRID_USE_GMSSL)
  if (LIBOQS_FOUND)
    target_link_libraries(hybrid_crypto PUBLIC ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${LIBOQS_LIBRARIES})
  else()
    target_link_libraries(hybrid_crypto PUBLIC ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY} ${OQS_LIBRARY})
  endif()
else()
  if (LIBOQS_FOUND)
    target_link_libraries(hybrid_crypto PUBLIC OpenSSL::Crypto ${LIBOQS_LIBRARIES})
  else()
    target_link_libraries(hybrid_crypto PUBLIC OpenSSL::Crypto ${OQS_LIBRARY})
  endif()
endif()

if (HYBRID_USE_GMSSL)
  if (UNIX)
    target_link_libraries(hybrid_crypto PUBLIC m pthread dl)
  endif()
endif()

if (HYBRID_BUILD_APPS)
  add_executable(hybrid_server apps/hybrid_server.c)
  add_executable(hybrid_client apps/hybrid_client.c)
  target_link_libraries(hybrid_server hybrid_crypto)
  target_link_libraries(hybrid_client hybrid_crypto)
endif()

if (HYBRID_BUILD_TESTS)
  add_executable(run_tests test/test_main.c)
  target_link_libraries(run_tests hybrid_crypto)
endif()


