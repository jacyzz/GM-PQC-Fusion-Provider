#!/usr/bin/env bash
set -euo pipefail

export OPENSSL_CONF=${OPENSSL_CONF:-}

echo "[check] openssl version" && openssl version -a
echo "[check] liboqs version (pkg-config)"
if ! pkg-config --modversion liboqs; then
  echo "[error] liboqs not found via pkg-config" >&2
  exit 1
fi

echo "[check] liboqs .so installed in /usr/local/lib64"
ls -l /usr/local/lib64 | grep -E 'liboqs.so' || (echo "[error] liboqs .so missing in /usr/local/lib64" >&2; exit 1)

echo "[check] generate SM2 key and self-signed cert"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out /tmp/sm2.key >/dev/null 2>&1
openssl req -new -x509 -sm3 -key /tmp/sm2.key -subj "/CN=DevContainer SM2" -out /tmp/sm2.crt -days 10 >/dev/null 2>&1

echo "[check] GmSSL static libraries present"
test -f /opt/gmssl/lib/libcrypto.a && test -f /opt/gmssl/lib/libssl.a || (echo "[error] GmSSL static libs missing in /opt/gmssl/lib" >&2; exit 1)

echo "[ok] environment is ready"



