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
ARG LIBOQS_REF=0.10.0

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

# Build and install liboqs 0.10.0 (shared to lib64)
RUN set -eux; \
  git clone --depth=1 --branch ${LIBOQS_REF} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs; \
  cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON \
    -DOPENSSL_ROOT_DIR=/usr/local \
    -DOPENSSL_INCLUDE_DIR=/usr/local/include \
    -DOPENSSL_CRYPTO_LIBRARY=/usr/local/lib64/libcrypto.so \
    -DOPENSSL_SSL_LIBRARY=/usr/local/lib64/libssl.so \
    -DCMAKE_INSTALL_LIBDIR=lib64; \
  cmake --build /tmp/liboqs/build --target install; \
  ldconfig; \
  rm -rf /tmp/liboqs

# Build and install GmSSL as static library into /opt/gmssl (isolated)
RUN set -eux; \
  git clone --depth=1 https://github.com/guanzhi/GmSSL.git /tmp/gmssl; \
  cd /tmp/gmssl; \
  ./config no-shared --prefix=/opt/gmssl; \
  make -j"$(nproc)"; \
  make install_sw; \
  rm -rf /tmp/gmssl

ENV PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH \
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
RUN set -eux; \
  openssl version -a; \
  pkg-config --modversion liboqs || true; \
  test -f /opt/gmssl/lib/libcrypto.a && test -f /opt/gmssl/lib/libssl.a; \
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out /tmp/sm2.key >/dev/null 2>&1 || true

CMD ["sleep", "infinity"]



