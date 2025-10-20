#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include "../include/hybrid_common.h"
#include "../include/hybrid_kex.h"
#include <oqs/oqs.h>

static int generate_sm2_keypair_raw(uint8_t *sm2_pub65_out, uint8_t *sm2_priv32_out) {
    int ret = HYBRID_ERROR_OPENSSL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_bn = NULL;
    const EC_POINT *pub_pt = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) goto end;
    if (EC_KEY_generate_key(ec_key) != 1) goto end;

    group = EC_KEY_get0_group(ec_key);
    pub_pt = EC_KEY_get0_public_key(ec_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!group || !pub_pt || !priv_bn) goto end;

    // export public key as uncompressed (65 bytes)
    size_t pub_len = EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                                         sm2_pub65_out, SM2_PUBKEY_LEN, NULL);
    if (pub_len != SM2_PUBKEY_LEN) goto end;

    // export private as 32-byte big-endian
    if (BN_bn2binpad(priv_bn, sm2_priv32_out, SM2_PRIKEY_LEN) != SM2_PRIKEY_LEN) goto end;

    ret = HYBRID_SUCCESS;
end:
    if (ec_key) EC_KEY_free(ec_key);
    return ret;
}

static int sm2_pub_from_priv(const uint8_t *sm2_priv32, uint8_t *sm2_pub65_out) {
    int ret = HYBRID_ERROR_OPENSSL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *priv_bn = NULL;
    EC_POINT *pub_pt = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group) goto end;
    ec_key = EC_KEY_new();
    if (!ec_key) goto end;
    if (EC_KEY_set_group(ec_key, group) != 1) goto end;
    priv_bn = BN_bin2bn(sm2_priv32, SM2_PRIKEY_LEN, NULL);
    if (!priv_bn) goto end;
    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) goto end;
    pub_pt = EC_POINT_new(group);
    if (!pub_pt) goto end;
    if (EC_POINT_mul(group, pub_pt, priv_bn, NULL, NULL, NULL) != 1) goto end;
    if (EC_KEY_set_public_key(ec_key, pub_pt) != 1) goto end;
    size_t pub_len = EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                                         sm2_pub65_out, SM2_PUBKEY_LEN, NULL);
    if (pub_len != SM2_PUBKEY_LEN) goto end;
    ret = HYBRID_SUCCESS;
end:
    if (pub_pt) EC_POINT_free(pub_pt);
    if (priv_bn) BN_free(priv_bn);
    if (ec_key) EC_KEY_free(ec_key);
    if (group) EC_GROUP_free(group);
    return ret;
}

static int compute_sm2_ecdh_shared(const uint8_t *local_priv32, const uint8_t *peer_pub65,
                                   uint8_t *out_ss, size_t *out_len) {
    int ret = HYBRID_ERROR_OPENSSL;
    EC_GROUP *group = NULL;
    EC_KEY *local_key = NULL;
    EC_POINT *peer_pt = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group) goto end;

    local_key = EC_KEY_new();
    if (!local_key) goto end;
    if (EC_KEY_set_group(local_key, group) != 1) goto end;
    BIGNUM *priv_bn = BN_bin2bn(local_priv32, SM2_PRIKEY_LEN, NULL);
    if (!priv_bn) goto end;
    if (EC_KEY_set_private_key(local_key, priv_bn) != 1) { BN_free(priv_bn); goto end; }
    BN_free(priv_bn);

    peer_pt = EC_POINT_new(group);
    if (!peer_pt) goto end;
    if (EC_POINT_oct2point(group, peer_pt, peer_pub65, SM2_PUBKEY_LEN, NULL) != 1) goto end;

    // Compute ECDH raw shared secret with low-level API to avoid EVP/SM2 quirks
    uint8_t secret[32];
    int s = ECDH_compute_key(secret, sizeof(secret), peer_pt, local_key, NULL);
    if (s <= 0) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    // KDF: SM3(secret) -> 32 bytes
    unsigned int md_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto end;
    if (EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL) != 1) { EVP_MD_CTX_free(mdctx); goto end; }
    if (EVP_DigestUpdate(mdctx, secret, (size_t)s) != 1) { EVP_MD_CTX_free(mdctx); goto end; }
    if (EVP_DigestFinal_ex(mdctx, out_ss, &md_len) != 1) { EVP_MD_CTX_free(mdctx); goto end; }
    EVP_MD_CTX_free(mdctx);
    *out_len = HYBRID_SHARED_SECRET_LEN;
    ret = HYBRID_SUCCESS;
end:
    if (peer_pt) EC_POINT_free(peer_pt);
    if (local_key) EC_KEY_free(local_key);
    if (group) EC_GROUP_free(group);
    return ret;
}

static void sm3_derive_final_shared(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                                    uint8_t *out32) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int md_len = 0;
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, a, a_len);
    EVP_DigestUpdate(mdctx, b, b_len);
    EVP_DigestFinal_ex(mdctx, out32, &md_len);
    EVP_MD_CTX_free(mdctx);
}

int hybrid_kex_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
) {
    if (!public_key || !public_key_len || !private_key || !private_key_len) return HYBRID_ERROR_PARAM;

    int rc = HYBRID_ERROR_LIBOQS;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    if (!kem) return HYBRID_ERROR_LIBOQS;

    uint8_t sm2_pub[SM2_PUBKEY_LEN];
    uint8_t sm2_priv[SM2_PRIKEY_LEN];
    if (generate_sm2_keypair_raw(sm2_pub, sm2_priv) != HYBRID_SUCCESS) { OQS_KEM_free(kem); return HYBRID_ERROR_OPENSSL; }

    uint8_t *mlkem_pub = (uint8_t*)malloc(kem->length_public_key);
    uint8_t *mlkem_priv = (uint8_t*)malloc(kem->length_secret_key);
    if (!mlkem_pub || !mlkem_priv) { free(mlkem_pub); free(mlkem_priv); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    if (OQS_KEM_keypair(kem, mlkem_pub, mlkem_priv) != OQS_SUCCESS) { free(mlkem_pub); free(mlkem_priv); OQS_KEM_free(kem); return HYBRID_ERROR_LIBOQS; }

    *public_key_len = SM2_PUBKEY_LEN + kem->length_public_key;
    *public_key = (uint8_t*)malloc(*public_key_len);
    *private_key_len = SM2_PRIKEY_LEN + kem->length_secret_key;
    *private_key = (uint8_t*)malloc(*private_key_len);
    if (!*public_key || !*private_key) { free(*public_key); free(*private_key); free(mlkem_pub); free(mlkem_priv); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }

    memcpy(*public_key, sm2_pub, SM2_PUBKEY_LEN);
    memcpy(*public_key + SM2_PUBKEY_LEN, mlkem_pub, kem->length_public_key);
    memcpy(*private_key, sm2_priv, SM2_PRIKEY_LEN);
    memcpy(*private_key + SM2_PRIKEY_LEN, mlkem_priv, kem->length_secret_key);

    free(mlkem_pub);
    free(mlkem_priv);
    OQS_KEM_free(kem);
    return HYBRID_SUCCESS;
}

int hybrid_kex_server_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    uint8_t **server_response, size_t *server_response_len,
    const uint8_t *client_public_key, size_t client_public_key_len,
    const uint8_t *server_private_key, size_t server_private_key_len
) {
    if (!shared_secret || !shared_secret_len || !server_response || !server_response_len ||
        !client_public_key || !server_private_key) return HYBRID_ERROR_PARAM;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    if (!kem) return HYBRID_ERROR_LIBOQS;

    if (client_public_key_len != SM2_PUBKEY_LEN + kem->length_public_key ||
        server_private_key_len != SM2_PRIKEY_LEN + kem->length_secret_key) {
        OQS_KEM_free(kem);
        return HYBRID_ERROR_PARAM;
    }

    const uint8_t *client_sm2_pub = client_public_key;
    const uint8_t *client_mlkem_pub = client_public_key + SM2_PUBKEY_LEN;
    const uint8_t *server_sm2_priv = server_private_key;
    const uint8_t *server_mlkem_priv = server_private_key + SM2_PRIKEY_LEN; // for completeness; not used here
    (void)server_mlkem_priv;

    // ECDH using server SM2 static priv and client SM2 pub
    uint8_t ss_sm2[HYBRID_SHARED_SECRET_LEN];
    size_t ss_sm2_len = 0;
    if (compute_sm2_ecdh_shared(server_sm2_priv, client_sm2_pub, ss_sm2, &ss_sm2_len) != HYBRID_SUCCESS) { OQS_KEM_free(kem); return HYBRID_ERROR_KEX_DERIVE; }

    // KEM encaps to client's ML-KEM pub
    uint8_t *ciphertext = (uint8_t*)malloc(kem->length_ciphertext);
    uint8_t *ss_mlkem = (uint8_t*)malloc(kem->length_shared_secret);
    if (!ciphertext || !ss_mlkem) { free(ciphertext); free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    if (OQS_KEM_encaps(kem, ciphertext, ss_mlkem, client_mlkem_pub) != OQS_SUCCESS) {
        free(ciphertext); free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_LIBOQS;
    }

    // Build server SM2 public from private for response
    uint8_t server_sm2_pub[SM2_PUBKEY_LEN];
    if (sm2_pub_from_priv(server_sm2_priv, server_sm2_pub) != HYBRID_SUCCESS) {
        free(ciphertext); free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_OPENSSL;
    }

    *server_response_len = SM2_PUBKEY_LEN + kem->length_ciphertext;
    *server_response = (uint8_t*)malloc(*server_response_len);
    if (!*server_response) { free(ciphertext); free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    memcpy(*server_response, server_sm2_pub, SM2_PUBKEY_LEN);
    memcpy(*server_response + SM2_PUBKEY_LEN, ciphertext, kem->length_ciphertext);

    // Derive final shared
    *shared_secret = (uint8_t*)malloc(HYBRID_SHARED_SECRET_LEN);
    if (!*shared_secret) { free(ciphertext); free(ss_mlkem); free(*server_response); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    sm3_derive_final_shared(ss_sm2, ss_sm2_len, ss_mlkem, kem->length_shared_secret, *shared_secret);
    *shared_secret_len = HYBRID_SHARED_SECRET_LEN;

    free(ciphertext);
    free(ss_mlkem);
    OQS_KEM_free(kem);
    return HYBRID_SUCCESS;
}

int hybrid_kex_client_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    const uint8_t *server_response, size_t server_response_len,
    const uint8_t *client_private_key, size_t client_private_key_len
) {
    if (!shared_secret || !shared_secret_len || !server_response || !client_private_key) return HYBRID_ERROR_PARAM;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEX_ALG);
    if (!kem) return HYBRID_ERROR_LIBOQS;

    if (server_response_len != SM2_PUBKEY_LEN + kem->length_ciphertext ||
        client_private_key_len != SM2_PRIKEY_LEN + kem->length_secret_key) {
        OQS_KEM_free(kem);
        return HYBRID_ERROR_PARAM;
    }

    const uint8_t *server_sm2_pub = server_response;
    const uint8_t *ciphertext = server_response + SM2_PUBKEY_LEN;
    const uint8_t *client_sm2_priv = client_private_key;
    const uint8_t *client_mlkem_priv = client_private_key + SM2_PRIKEY_LEN;

    uint8_t ss_sm2[HYBRID_SHARED_SECRET_LEN];
    size_t ss_sm2_len = 0;
    if (compute_sm2_ecdh_shared(client_sm2_priv, server_sm2_pub, ss_sm2, &ss_sm2_len) != HYBRID_SUCCESS) { OQS_KEM_free(kem); return HYBRID_ERROR_KEX_DERIVE; }

    uint8_t *ss_mlkem = (uint8_t*)malloc(kem->length_shared_secret);
    if (!ss_mlkem) { OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    if (OQS_KEM_decaps(kem, ss_mlkem, ciphertext, client_mlkem_priv) != OQS_SUCCESS) { free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_LIBOQS; }

    *shared_secret = (uint8_t*)malloc(HYBRID_SHARED_SECRET_LEN);
    if (!*shared_secret) { free(ss_mlkem); OQS_KEM_free(kem); return HYBRID_ERROR_MALLOC; }
    sm3_derive_final_shared(ss_sm2, ss_sm2_len, ss_mlkem, kem->length_shared_secret, *shared_secret);
    *shared_secret_len = HYBRID_SHARED_SECRET_LEN;

    free(ss_mlkem);
    OQS_KEM_free(kem);
    return HYBRID_SUCCESS;
}


