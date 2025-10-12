# Examples quickstart (Scheme A: OpenSSL-native GM + PQC)

This folder contains three minimal demos built on OpenSSL 3 providers:
- kem_demo: local KEM roundtrip
- server/client: tiny KEM-based handshake, then AEAD-encrypted data frames

In Scheme A we use:
- PQC KEM via oqsprovider (or your custom provider once ready)
- GM side via OpenSSL 3 native primitives (no GmSSL linking in provider)
- HKDF-SHA3(256) to derive traffic key/iv; AEAD = AES-128-GCM

## Prerequisites (inside container)
- OpenSSL 3.x under /usr/local (preinstalled in the devcontainer)
- oqsprovider at /usr/local/lib64/ossl-modules/oqsprovider.so
- Env: OPENSSL_MODULES=/usr/local/lib64/ossl-modules

Optional checks:
- openssl list -providers -provider oqsprovider -provider default
- openssl list -kem-algorithms -provider oqsprovider -provider default

## Build
- make -C examples -j

## Run with oqsprovider
1) Server (adjust KEM name to your build, e.g., mlkem768)
- ./server --mode pqc --provider oqsprovider --kem mlkem768 --aead aes-128-gcm --listen 0.0.0.0:8443 --n 1000
2) Client
- ./client --mode pqc --provider oqsprovider --connect 127.0.0.1:8443 --aead aes-128-gcm --payload 1024 --n 1000

Expected: both sides print metrics; no encap/decap/HKDF/AEAD errors.

Notes:
- The client learns the KEM name from ServerHello and follows it.
- For production, use distinct HKDF labels and a transcript-bound salt.

## Switch to your custom provider (once installed)
- Install your provider module (.so) to the OpenSSL modules dir (or set OPENSSL_MODULES), then run:
- ./server --mode pqc --provider gmpqcprovider --kem SM2-ML-KEM-768 --aead aes-128-gcm --listen 0.0.0.0:8443
- ./client --mode pqc --provider gmpqcprovider --connect 127.0.0.1:8443 --aead aes-128-gcm

For drop-in replacement, your provider must implement KEYMGMT (gen/import/export) and KEM (encap/decap).
