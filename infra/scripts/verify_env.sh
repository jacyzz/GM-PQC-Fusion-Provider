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

echo "[check] oqsprovider module file"
MOD_DIR=${OPENSSL_MODULES:-/usr/local/lib64/ossl-modules}
if [ -f "$MOD_DIR/oqsprovider.so" ]; then
  echo "[ok] $MOD_DIR/oqsprovider.so"
else
  echo "[warn] $MOD_DIR/oqsprovider.so not found; installation may differ" >&2
fi

echo "[check] oqsprovider availability via -provider"
if openssl list -kem-algorithms -provider oqsprovider -provider default >/dev/null 2>&1; then
  echo "[ok] oqsprovider responds to KEM listing"
else
  echo "[error] failed to query oqsprovider KEMs; check OPENSSL_MODULES and installation" >&2
  echo "OPENSSL_MODULES=${OPENSSL_MODULES:-}"
  exit 1
fi

echo "[check] quick SM2 sign/verify and optional encrypt/decrypt"
TMPD=$(mktemp -d)
echo "hello-sm2" > "$TMPD/msg.bin"
openssl ecparam -name SM2 -genkey -noout -out "$TMPD/sm2.key"
openssl pkey -in "$TMPD/sm2.key" -pubout -out "$TMPD/sm2.pub"
# SM2 sign/verify with SM3
openssl dgst -sm3 -sign "$TMPD/sm2.key" -out "$TMPD/sig.bin" "$TMPD/msg.bin"
if openssl dgst -sm3 -verify "$TMPD/sm2.pub" -signature "$TMPD/sig.bin" "$TMPD/msg.bin" >/dev/null 2>&1; then
  echo "[ok] SM2 sign/verify"
else
  echo "[error] SM2 sign/verify failed" >&2; rm -rf "$TMPD"; exit 1
fi
# Optional encrypt/decrypt (parameter names vary across builds)
if openssl pkeyutl -encrypt -inkey "$TMPD/sm2.pub" -pubin \
  -in "$TMPD/msg.bin" -out "$TMPD/ct.bin" \
  -pkeyopt sm2_id:1234567812345678 >/dev/null 2>&1; then
  if openssl pkeyutl -decrypt -inkey "$TMPD/sm2.key" \
    -in "$TMPD/ct.bin" -out "$TMPD/pt.bin" \
    -pkeyopt sm2_id:1234567812345678 >/dev/null 2>&1; then
    if diff "$TMPD/msg.bin" "$TMPD/pt.bin" >/dev/null; then
      echo "[ok] SM2 encrypt/decrypt"
    else
      echo "[warn] SM2 decrypt mismatch" >&2
    fi
  else
    echo "[warn] SM2 decrypt not supported in this build" >&2
  fi
else
  echo "[warn] SM2 encrypt not supported in this OpenSSL build; skipped" >&2
fi
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


