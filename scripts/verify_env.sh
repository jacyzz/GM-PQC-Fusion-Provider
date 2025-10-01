#!/usr/bin/env bash
set -euo pipefail

export OPENSSL_CONF=${OPENSSL_CONF:-}

echo "[check] openssl version" && openssl version -a
echo "[check] liboqs version (pkg-config)"
if ! pkg-config --modversion liboqs; then
  echo "[warn] pkg-config failed, fallback to file check" >&2
else
  echo "[ok] liboqs via pkg-config" >&2
fi

echo "[check] liboqs .so installed"
if ! ls -l /usr/local/lib64 | grep -E 'liboqs.so'; then
  if ! ls -l /usr/local/lib | grep -E 'liboqs.so'; then
    echo "[error] liboqs .so not found in /usr/local/lib64 or /usr/local/lib" >&2; exit 1
  fi
fi

echo "[check] generate SM2 key and self-signed cert"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out /tmp/sm2.key >/dev/null 2>&1
openssl req -new -x509 -sm3 -key /tmp/sm2.key -subj "/CN=DevContainer SM2" -out /tmp/sm2.crt -days 10 >/dev/null 2>&1

echo "[check] GmSSL static libraries present"
if [ -f /opt/gmssl/lib/libgmssl.a ]; then
  echo "[ok] found /opt/gmssl/lib/libgmssl.a"
elif [ -f /opt/gmssl/lib/libcrypto.a ] && [ -f /opt/gmssl/lib/libssl.a ]; then
  echo "[ok] found /opt/gmssl/lib/libcrypto.a and libssl.a"
else
  echo "[error] GmSSL static libs not found (expected libgmssl.a or libssl.a+libcrypto.a under /opt/gmssl/lib)" >&2
  exit 1
fi

if [ -x /opt/gmssl/bin/gmssl ]; then
  echo "[check] gmssl version" && /opt/gmssl/bin/gmssl version || true
fi

echo "[ok] environment is ready"



