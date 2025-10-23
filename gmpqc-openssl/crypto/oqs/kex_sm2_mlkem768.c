/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/oqs.h>
#include <oqs/oqs.h>
#include "oqs_meth.h"
#include "internal/oqs_kex.h"

/*
 * This function is adapted from hybrid_crypto/src/hybrid_kex.c
 * It generates a raw SM2 keypair.
 * Note: oqs-openssl uses i2o/o2i format for public keys, which is different
 * from the raw uncompressed format in hybrid_crypto. For simplicity, we will
 * stick to raw format here and handle conversions at the boundary.
 */
static int sm2_generate_key_raw(unsigned char* pubkey, unsigned char* privkey) {
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_bn = NULL;
    const EC_POINT *pub_pt = NULL;
    int ret = 0;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) goto err;
    if (EC_KEY_generate_key(ec_key) != 1) goto err;

    group = EC_KEY_get0_group(ec_key);
    pub_pt = EC_KEY_get0_public_key(ec_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!group || !pub_pt || !priv_bn) goto err;

    // export public key as uncompressed (65 bytes)
    if (EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                           pubkey, 65, NULL) != 65) goto err;

    // export private as 32-byte big-endian
    if (BN_bn2binpad(priv_bn, privkey, 32) != 32) goto err;

    ret = 1;
err:
    if (ec_key) EC_KEY_free(ec_key);
    return ret;
}

/*
 * This function is adapted from hybrid_crypto/src/hybrid_kex.c
 * It computes the raw SM2 ECDH shared secret.
 */
static int sm2_compute_key_raw(unsigned char **pms, size_t *pmslen,
                               const unsigned char *pubkey, size_t pubkey_len,
                               EC_KEY *privkey) {
    EC_POINT *peer_pt = NULL;
    const EC_GROUP *group = NULL;
    int ret = 0;
    int secret_len;

    if (privkey == NULL) return 0;
    group = EC_KEY_get0_group(privkey);
    if (group == NULL) goto err;

    peer_pt = EC_POINT_new(group);
    if (peer_pt == NULL) goto err;
    if (EC_POINT_oct2point(group, peer_pt, pubkey, pubkey_len, NULL) != 1) goto err;

    *pmslen = 32; /* SM2 shared secret size */
    *pms = OPENSSL_malloc(*pmslen);
    if (*pms == NULL) goto err;

    secret_len = ECDH_compute_key(*pms, *pmslen, peer_pt, privkey, NULL);
    if (secret_len <= 0) {
        OPENSSL_free(*pms);
        *pms = NULL;
        goto err;
    }
    *pmslen = secret_len;

    ret = 1;
err:
    if (peer_pt) EC_POINT_free(peer_pt);
    return ret;
}

OQS_KEM *oqs_sm2_mlkem768_new(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) return NULL;

    OQS_KEM *sm2_kem = OPENSSL_zalloc(sizeof(OQS_KEM));
    if (sm2_kem == NULL) {
        OQS_KEM_free(kem);
        return NULL;
    }

    sm2_kem->method_name = OQS_KEM_alg_sm2_mlkem768;
    sm2_kem->alg_name = "sm2_mlkem768";
    sm2_kem->is_hybrid = 1;

    sm2_kem->length_public_key = 65 + kem->length_public_key;
    sm2_kem->length_secret_key = 32 + kem->length_secret_key;
    sm2_kem->length_ciphertext = 65 + kem->length_ciphertext;
    sm2_kem->length_shared_secret = 32 + kem->length_shared_secret;

    sm2_kem->keypair = oqs_hybrid_keypair;
    sm2_kem->encaps = oqs_hybrid_encaps;
    sm2_kem->decaps = oqs_hybrid_decaps;

    struct oqs_hybrid_kex_ctx *h = OPENSSL_zalloc(sizeof(struct oqs_hybrid_kex_ctx));
    if (h == NULL) {
        OQS_KEM_free(kem);
        OPENSSL_free(sm2_kem);
        return NULL;
    }

    h->local_kex_method.generate_key_custom = sm2_generate_key_raw;
    h->local_kex_method.compute_key_custom = sm2_compute_key_raw;
    h->local_kex_method.EVP_PKEY_CTX_set_app_data = NULL;
    h->local_pubkey_len = 65;
    h->local_privkey_len = 32;
    h->oqs_kex_method = kem;

    sm2_kem->ctx = h;
    return sm2_kem;
}
