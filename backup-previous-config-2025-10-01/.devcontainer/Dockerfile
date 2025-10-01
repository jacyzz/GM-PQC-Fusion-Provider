FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# Base packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git curl ca-certificates \
    pkg-config nasm clang sudo autoconf automake libtool \
    python3 python3-pip unzip zip xz-utils file \
    && rm -rf /var/lib/apt/lists/* && update-ca-certificates

ARG OPENSSL_VERSION=3.2.1
ARG LIBOQS_REF=main
ARG OQSPROV_REF=main

# Build and install OpenSSL 3 (with SM2/SM3/SM4 enabled)
RUN set -eux; \
  apt-get update && apt-get install -y --no-install-recommends git make perl \
  && rm -rf /var/lib/apt/lists/*; \
  git clone --depth=1 --branch openssl-${OPENSSL_VERSION} https://github.com/openssl/openssl.git /tmp/openssl; \
  cd /tmp/openssl; \
  ARCH=$(uname -m); \
  case "$ARCH" in \
    x86_64) TARGET=linux-x86_64 ;; \
    aarch64|arm64) TARGET=linux-aarch64 ;; \
    *) TARGET=linux-generic64 ;; \
  esac; \
  ./Configure ${TARGET} enable-sm2 enable-sm3 enable-sm4 shared threads no-ssl3 no-comp no-zlib; \
  make -j"$(nproc)"; \
  make install_sw; \
  echo "/usr/local/lib64" > /etc/ld.so.conf.d/openssl-lib64.conf; \
  ldconfig; \
  openssl version -a; \
  rm -rf /tmp/openssl

# Build and install liboqs (shared)
RUN set -eux; \
  git clone --depth=1 --branch ${LIBOQS_REF} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs; \
  cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON \
    -DOPENSSL_ROOT_DIR=/usr/local \
    -DOPENSSL_INCLUDE_DIR=/usr/local/include \
    -DOPENSSL_CRYPTO_LIBRARY=/usr/local/lib64/libcrypto.so \
    -DOPENSSL_SSL_LIBRARY=/usr/local/lib64/libssl.so; \
  cmake --build /tmp/liboqs/build --target install; \
  ldconfig; \
  rm -rf /tmp/liboqs

# Build and install oqs-provider
RUN set -eux; \
  git clone --depth=1 --branch ${OQSPROV_REF} https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider; \
  cmake -S /tmp/oqs-provider -B /tmp/oqs-provider/build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=/usr/local \
    -DOPENSSL_INCLUDE_DIR=/usr/local/include \
    -DOPENSSL_CRYPTO_LIBRARY=/usr/local/lib64/libcrypto.so \
    -DOPENSSL_SSL_LIBRARY=/usr/local/lib64/libssl.so \
    -DOQS_PROVIDER_BUILD_SHARED=ON; \
  cmake --build /tmp/oqs-provider/build --target install; \
  ldconfig; \
  rm -rf /tmp/oqs-provider

# Configure OpenSSL providers via a dedicated config file
RUN set -eux; \
  mkdir -p /usr/local/etc; \
  printf '%s\n' \
    ".openssl_conf = openssl_init" \
    "" \
    "[openssl_init]" \
    "providers = provider_sect" \
    "alg_section = algorithm_sect" \
    "" \
    "[provider_sect]" \
    "default = default_sect" \
    "oqsprovider = oqs_sect" \
    "" \
    "[default_sect]" \
    "activate = 1" \
    "" \
    "[oqs_sect]" \
    "module = /usr/local/lib64/ossl-modules/oqsprovider.so" \
    "activate = 1" \
    "" \
    "[algorithm_sect]" \
    "# keep defaults" \
    > /usr/local/etc/openssl-hybrid.cnf

ENV OPENSSL_CONF=/usr/local/etc/openssl-hybrid.cnf \
    OPENSSL_MODULES=/usr/local/lib64/ossl-modules \
    PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH \
    LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH

# Create non-root user for devcontainers
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000
RUN groupadd --gid ${USER_GID} ${USERNAME} \
  && useradd -s /bin/bash --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} \
  && apt-get update && apt-get install -y --no-install-recommends sudo \
  && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
  && chmod 0440 /etc/sudoers.d/${USERNAME} \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspaces/project
USER ${USERNAME}

# Quick self-check on image build
RUN openssl list -providers \
  && OPENSSL_MODULES=/usr/local/lib64/ossl-modules openssl list -provider oqsprovider -kem-algorithms | head -n 5 || true

CMD ["sleep", "infinity"]



