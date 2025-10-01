#!/usr/bin/env bash
set -euo pipefail

echo "[check] openssl version" && openssl version -a

echo "[check] liboqs version (pkg-config)"
if ! pkg-config --modversion liboqs; then
  echo "[warn] pkg-config failed, fallback to file check" >&2
else
  echo "[ok] liboqs via pkg-config" >&2
fi

echo "[check] liboqs .so installed"
if ! ls -l /usr/local/lib64 | grep -E 'liboqs.so' >/dev/null 2>&1; then
  if ! ls -l /usr/local/lib | grep -E 'liboqs.so' >/dev/null 2>&1; then
    echo "[error] liboqs .so not found in /usr/local/lib64 or /usr/local/lib" >&2; exit 1
  fi
fi

echo "[check] OpenSSL providers (expect oqsprovider present)"
if ! openssl list -providers | grep -q 'oqsprovider'; then
  echo "[error] oqsprovider not listed by openssl; check OPENSSL_MODULES and installation" >&2
  echo "OPENSSL_MODULES=${OPENSSL_MODULES:-}"
  exit 1
fi

echo "[check] oqsprovider KEM algorithms"
openssl list -kem-algorithms -provider oqsprovider -provider default || true

echo "[check] quick SM2 encrypt/decrypt roundtrip"
TMPD=$(mktemp -d)
echo "hello-sm2" > "$TMPD/msg.bin"
openssl ecparam -name SM2 -genkey -noout -out "$TMPD/sm2.key"
openssl pkey -in "$TMPD/sm2.key" -pubout -out "$TMPD/sm2.pub"
openssl pkeyutl -encrypt -inkey "$TMPD/sm2.pub" -pubin \
  -pkeyopt ec_scheme:sm2 -pkeyopt sm2_id:1234567812345678 \
  -in "$TMPD/msg.bin" -out "$TMPD/ct.bin"
openssl pkeyutl -decrypt -inkey "$TMPD/sm2.key" \
  -pkeyopt ec_scheme:sm2 -pkeyopt sm2_id:1234567812345678 \
  -in "$TMPD/ct.bin" -out "$TMPD/pt.bin"
diff "$TMPD/msg.bin" "$TMPD/pt.bin" >/dev/null && echo "[ok] SM2 roundtrip"
rm -rf "$TMPD"

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


