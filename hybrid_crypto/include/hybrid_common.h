#ifndef HYBRID_COMMON_H
#define HYBRID_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <oqs/oqs.h>

// PQC algorithm selections (liboqs)
#define HYBRID_KEX_ALG "sm2_mlkem768"
#define HYBRID_SIG_ALG "sm2_mldsa65"

// liboqs concrete algorithms (handle naming across liboqs versions)
#if defined(OQS_KEM_alg_ml_kem_768)
#define OQS_KEX_ALG OQS_KEM_alg_ml_kem_768
#elif defined(OQS_KEM_alg_kyber_768)
#define OQS_KEX_ALG OQS_KEM_alg_kyber_768
#else
#error "liboqs: required KEM (Kyber/ML-KEM 768) not available"
#endif

#if defined(OQS_SIG_alg_ml_dsa_65)
#define OQS_SIG_ALG OQS_SIG_alg_ml_dsa_65
#elif defined(OQS_SIG_alg_dilithium_3)
#define OQS_SIG_ALG OQS_SIG_alg_dilithium_3
#else
#error "liboqs: required SIG (Dilithium/ML-DSA level 3/65) not available"
#endif

// SM2 fixed sizes
#define SM2_PUBKEY_LEN 65 /* uncompressed: 0x04 + 32-byte X + 32-byte Y */
#define SM2_PRIKEY_LEN 32 /* 32-byte scalar */

// Shared secret size after KDF (SM3)
#define HYBRID_SHARED_SECRET_LEN 32

// Error codes
#define HYBRID_SUCCESS 0
#define HYBRID_ERROR_MALLOC -1
#define HYBRID_ERROR_PARAM -2
#define HYBRID_ERROR_OPENSSL -3
#define HYBRID_ERROR_LIBOQS -4

#define HYBRID_ERROR_KEX_KEYGEN -10
#define HYBRID_ERROR_KEX_DERIVE -11

#define HYBRID_ERROR_SIG_KEYGEN -20
#define HYBRID_ERROR_SIG_SIGN -21
#define HYBRID_ERROR_SIG_VERIFY -22

// helper to free buffers allocated by the module
void free_key_data(uint8_t *key_data);

#endif /* HYBRID_COMMON_H */

