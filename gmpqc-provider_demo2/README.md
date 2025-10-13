# GMPQC provider demo (Scheme A notes)

Goal
- Provide a custom OpenSSL 3 provider exposing a KEM usable by the examples without changing application code.

Scheme A guidance
- Do NOT link GmSSL into the provider to avoid symbol/ABI conflicts with OpenSSL 3.
- Use OpenSSL 3 native SM2/SM3/SM4 if GM is needed; or keep GM+PQC fusion at the application layer for now.

What is needed for drop-in replacement
- Implement KEYMGMT for your KEM type:
  - gen: produce a hybrid/public key as a single provider-side key object
  - import/export: support OSSL_PKEY_PARAM_PUB_KEY carrying the serialized public key bytes
  - has: report public/private presence
- Implement KEM:
  - encapsulate_init: receive vkey (peer public key) from KEYMGMT
  - decapsulate_init: receive vkey (private key) from KEYMGMT
  - encapsulate/decapsulate: produce ciphertext and shared secret

Algorithm naming
- Keep a stable name (e.g., SM2-ML-KEM-768). Optionally add a property string (provider=gmpqc) for precise fetching.

Build & install (inside container)
- Use CMake to produce a MODULE (no lib prefix). Install to ${CMAKE_INSTALL_LIBDIR}/ossl-modules.
- Ensure OPENSSL_MODULES points to that directory at runtime.

Sanity checks
- openssl list -providers -provider gmpqcprovider -provider default
- openssl list -kem-algorithms -provider gmpqcprovider -provider default

Troubleshooting
- kem keygen fail: KEYMGMT.gen is missing or algorithm name mismatch.
- import/export issues: ensure OSSL_PKEY_PARAM_PUB_KEY is supported by import/export.
- crash on load: verify ldd on your provider .so and avoid mixing GmSSL with OpenSSL 3 in the same process.
