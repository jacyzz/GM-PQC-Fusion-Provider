#pragma once
#include <stddef.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include "hybrid_crypto.h"

#define GMPQC_HYBRID_KEM_NAME "SM2-ML-KEM-768"
#define GMPQC_UNDERLYING_OQS_KEM "ML-KEM-768"

/* Opaque provider key type managed by KEYMGMT */
typedef struct gmpqc_key_st GMPQC_KEY;

/* Build serialized hybrid public key [2B | SM2 SPKI DER | OQS pk]; caller owns *out (OPENSSL_free ok). */
int gmpqc_keymgmt_get_serialized_pub(GMPQC_KEY *k, unsigned char **out, size_t *outlen);

/* Clone materials for decapsulation into a fresh hybrid secret key; caller frees via gmpqc_hybrid_secret_key_free. */
int gmpqc_keymgmt_clone_for_decap(GMPQC_KEY *k, gmpqc_hybrid_secret_key_t **out_sk);
