#!/usr/bin/env bash
set -euo pipefail

export OPENSSL_MODULES=${OPENSSL_MODULES:-/usr/local/lib64/ossl-modules}
export OPENSSL_CONF=${OPENSSL_CONF:-/usr/local/etc/openssl-hybrid.cnf}

echo "[check] openssl version" && openssl version -a
echo "[check] providers" && openssl list -providers

echo "[check] oqs-provider KEM list (expect ML-KEM entries)"
if ! OPENSSL_MODULES="$OPENSSL_MODULES" openssl list -provider oqsprovider -kem-algorithms | grep -i "ml-kem"; then
  echo "[error] oqs-provider not loaded or ML-KEM missing" >&2
  exit 1
fi

echo "[check] generate ML-DSA key"
OPENSSL_MODULES="$OPENSSL_MODULES" openssl genpkey -provider oqsprovider -algorithm mldsa44 -out /tmp/mldsa.key >/dev/null 2>&1

echo "[check] generate SM2 key and self-signed cert"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out /tmp/sm2.key >/dev/null 2>&1
openssl req -new -x509 -sm3 -key /tmp/sm2.key -subj "/CN=DevContainer SM2" -out /tmp/sm2.crt -days 10 >/dev/null 2>&1

echo "[ok] environment is ready"



