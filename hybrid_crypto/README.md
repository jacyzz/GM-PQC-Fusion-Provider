Hybrid Crypto (SM2/SM3/SM4 + Kyber/Dilithium)

This module provides hybrid key exchange (SM2 ECDH + Kyber/ML-KEM) and composite signatures (SM2 + Dilithium/ML-DSA) with a simple server/client demo using SM4-GCM for encrypted transport.

Build Requirements
- OpenSSL 3.x with SM2/SM3/SM4 enabled (default path: /usr/local)
- liboqs (shared; default path in /usr/local/lib64)
- Optional: GmSSL static libs in /opt/gmssl for GMSSL variant
- cmake >= 3.16, a C compiler

Your devcontainer image already satisfies these.

Build
```bash
cd hybrid_crypto
mkdir build && cd build
cmake ..
make -j
```

Build with GmSSL for SM2/SM3/SM4 instead of OpenSSL 3:
```bash
cmake .. -DHYBRID_USE_GMSSL=ON -DGMSSL_ROOT=/opt/gmssl
make -j
```

Tests
```bash
./run_tests
```
Expected output includes KEX and Signature tests passed.

Demo Apps
Two apps show a minimal handshake and SM4-GCM encrypted message exchange.
- hybrid_server [port] (default 5555)
- hybrid_client [host] [port]

Run locally (two terminals):
```bash
./apps/hybrid_server 5555
./apps/hybrid_client 127.0.0.1 5555
```
You should see derived shared-secret prefixes and a ping/pong exchange.

Running on Docker (two containers on one host)
Use your devcontainer image or build the provided Dockerfile. Example:
```bash
# terminal A (server)
docker run --rm -it -v $(pwd):/work -w /work hybrid-dev bash -lc "cd hybrid_crypto && mkdir -p build && cd build && cmake .. && make && ./apps/hybrid_server 5555"
# terminal B (client)
docker run --rm -it --network host -v $(pwd):/work -w /work hybrid-dev bash -lc "cd hybrid_crypto && ./build/apps/hybrid_client 127.0.0.1 5555"
```
If host networking is not available, run containers on a user-defined bridge and connect via the server container IP.

Running on two VMs
- Option A (recommended): install Docker and reuse the same devcontainer image on both VMs; mount this repo into the container and run the same build and app commands.
- Option B: native install OpenSSL 3 and liboqs on each VM, then build this project similarly to above and run server on VM1 and client on VM2.

API Overview
```c
int hybrid_kex_keygen(uint8_t **pub, size_t *pub_len, uint8_t **priv, size_t *priv_len);
int hybrid_kex_server_derive(uint8_t **shared, size_t *shared_len, uint8_t **resp, size_t *resp_len, const uint8_t *client_pub, size_t client_pub_len, const uint8_t *server_priv, size_t server_priv_len);
int hybrid_kex_client_derive(uint8_t **shared, size_t *shared_len, const uint8_t *resp, size_t resp_len, const uint8_t *client_priv, size_t client_priv_len);

int hybrid_sig_keygen(uint8_t **pub, size_t *pub_len, uint8_t **priv, size_t *priv_len);
int hybrid_sig_sign(uint8_t **sig, size_t *sig_len, const uint8_t *msg_digest, size_t digest_len, const uint8_t *priv, size_t priv_len);
int hybrid_sig_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg_digest, size_t digest_len, const uint8_t *pub, size_t pub_len);
```
- Public/Private keys are concatenations: `SM2_pub||MLKEM_pub` and `SM2_priv||MLKEM_sk` (or MLDSA variants).
- Shared secret is derived by SM3 over the concatenation of SM2 ECDH output and ML-KEM shared secret.
- Signatures concatenate `SM2_sig(DER)||MLDSA_sig`.

Notes
- For production, add identity binding, context strings in KDF, parameter validation, and side-channel considerations.
- The demo uses first 16 bytes of the shared secret as SM4-GCM key for simplicity.

