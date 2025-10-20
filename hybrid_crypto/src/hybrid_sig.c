#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "../include/hybrid_common.h"
#include "../include/hybrid_sig.h"
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

    size_t pub_len = EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                                         sm2_pub65_out, SM2_PUBKEY_LEN, NULL);
    if (pub_len != SM2_PUBKEY_LEN) goto end;
    if (BN_bn2binpad(priv_bn, sm2_priv32_out, SM2_PRIKEY_LEN) != SM2_PRIKEY_LEN) goto end;
    ret = HYBRID_SUCCESS;
end:
    if (ec_key) EC_KEY_free(ec_key);
    return ret;
}

static int sm2_sign_digest_der(const uint8_t *digest, size_t digest_len,
                               const uint8_t *sm2_priv32,
                               uint8_t **sig_der, size_t *sig_der_len) {
    int ret = HYBRID_ERROR_OPENSSL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    ECDSA_SIG *sig = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group) goto end;
    ec_key = EC_KEY_new();
    if (!ec_key) goto end;
    if (EC_KEY_set_group(ec_key, group) != 1) goto end;
    BIGNUM *priv = BN_bin2bn(sm2_priv32, SM2_PRIKEY_LEN, NULL);
    if (!priv) goto end;
    if (EC_KEY_set_private_key(ec_key, priv) != 1) { BN_free(priv); goto end; }
    BN_free(priv);

    sig = ECDSA_do_sign(digest, (int)digest_len, ec_key);
    if (!sig) goto end;

    int len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) goto end;
    *sig_der = (uint8_t*)malloc((size_t)len);
    if (!*sig_der) goto end;
    unsigned char *p = *sig_der;
    len = i2d_ECDSA_SIG(sig, &p);
    if (len <= 0) { free(*sig_der); *sig_der = NULL; goto end; }
    *sig_der_len = (size_t)len;
    ret = HYBRID_SUCCESS;
end:
    if (sig) ECDSA_SIG_free(sig);
    if (ec_key) EC_KEY_free(ec_key);
    if (group) EC_GROUP_free(group);
    return ret;
}

static int sm2_verify_digest_der(const uint8_t *digest, size_t digest_len,
                                 const uint8_t *sm2_pub65,
                                 const uint8_t *sig_der, size_t sig_der_len) {
    int ret = HYBRID_ERROR_OPENSSL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_pt = NULL;
    ECDSA_SIG *sig = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group) goto end;
    ec_key = EC_KEY_new();
    if (!ec_key) goto end;
    if (EC_KEY_set_group(ec_key, group) != 1) goto end;
    pub_pt = EC_POINT_new(group);
    if (!pub_pt) goto end;
    if (EC_POINT_oct2point(group, pub_pt, sm2_pub65, SM2_PUBKEY_LEN, NULL) != 1) goto end;
    if (EC_KEY_set_public_key(ec_key, pub_pt) != 1) goto end;

    const unsigned char *p = sig_der;
    sig = d2i_ECDSA_SIG(NULL, &p, (long)sig_der_len);
    if (!sig) goto end;

    int vr = ECDSA_do_verify(digest, (int)digest_len, sig, ec_key);
    if (vr != 1) { ret = HYBRID_ERROR_SIG_VERIFY; goto end; }
    ret = HYBRID_SUCCESS;
end:
    if (sig) ECDSA_SIG_free(sig);
    if (pub_pt) EC_POINT_free(pub_pt);
    if (ec_key) EC_KEY_free(ec_key);
    if (group) EC_GROUP_free(group);
    return ret;
}

int hybrid_sig_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
) {
    if (!public_key || !public_key_len || !private_key || !private_key_len) return HYBRID_ERROR_PARAM;

    OQS_SIG *oqs = OQS_SIG_new(OQS_SIG_ALG);
    if (!oqs) return HYBRID_ERROR_LIBOQS;

    uint8_t sm2_pub[SM2_PUBKEY_LEN];
    uint8_t sm2_priv[SM2_PRIKEY_LEN];
    if (generate_sm2_keypair_raw(sm2_pub, sm2_priv) != HYBRID_SUCCESS) { OQS_SIG_free(oqs); return HYBRID_ERROR_OPENSSL; }

    uint8_t *mldsa_pub = (uint8_t*)malloc(oqs->length_public_key);
    uint8_t *mldsa_priv = (uint8_t*)malloc(oqs->length_secret_key);
    if (!mldsa_pub || !mldsa_priv) { free(mldsa_pub); free(mldsa_priv); OQS_SIG_free(oqs); return HYBRID_ERROR_MALLOC; }
    if (OQS_SIG_keypair(oqs, mldsa_pub, mldsa_priv) != OQS_SUCCESS) { free(mldsa_pub); free(mldsa_priv); OQS_SIG_free(oqs); return HYBRID_ERROR_LIBOQS; }

    *public_key_len = SM2_PUBKEY_LEN + oqs->length_public_key;
    *private_key_len = SM2_PRIKEY_LEN + oqs->length_secret_key;
    *public_key = (uint8_t*)malloc(*public_key_len);
    *private_key = (uint8_t*)malloc(*private_key_len);
    if (!*public_key || !*private_key) { free(*public_key); free(*private_key); free(mldsa_pub); free(mldsa_priv); OQS_SIG_free(oqs); return HYBRID_ERROR_MALLOC; }

    memcpy(*public_key, sm2_pub, SM2_PUBKEY_LEN);
    memcpy(*public_key + SM2_PUBKEY_LEN, mldsa_pub, oqs->length_public_key);
    memcpy(*private_key, sm2_priv, SM2_PRIKEY_LEN);
    memcpy(*private_key + SM2_PRIKEY_LEN, mldsa_priv, oqs->length_secret_key);

    free(mldsa_pub);
    free(mldsa_priv);
    OQS_SIG_free(oqs);
    return HYBRID_SUCCESS;
}

int hybrid_sig_sign(
    uint8_t **signature, size_t *signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *private_key, size_t private_key_len
) {
    if (!signature || !signature_len || !message_digest || !private_key) return HYBRID_ERROR_PARAM;

    OQS_SIG *oqs = OQS_SIG_new(OQS_SIG_ALG);
    if (!oqs) return HYBRID_ERROR_LIBOQS;
    if (private_key_len != SM2_PRIKEY_LEN + oqs->length_secret_key) { OQS_SIG_free(oqs); return HYBRID_ERROR_PARAM; }

    const uint8_t *sm2_priv = private_key;
    const uint8_t *mldsa_priv = private_key + SM2_PRIKEY_LEN;

    uint8_t *sm2_sig_der = NULL;
    size_t sm2_sig_der_len = 0;
    if (sm2_sign_digest_der(message_digest, digest_len, sm2_priv, &sm2_sig_der, &sm2_sig_der_len) != HYBRID_SUCCESS) { OQS_SIG_free(oqs); return HYBRID_ERROR_SIG_SIGN; }

    uint8_t *mldsa_sig = (uint8_t*)malloc(oqs->length_signature);
    size_t mldsa_sig_len = 0;
    if (!mldsa_sig) { free(sm2_sig_der); OQS_SIG_free(oqs); return HYBRID_ERROR_MALLOC; }
    if (OQS_SIG_sign(oqs, mldsa_sig, &mldsa_sig_len, message_digest, digest_len, mldsa_priv) != OQS_SUCCESS) {
        free(sm2_sig_der); free(mldsa_sig); OQS_SIG_free(oqs); return HYBRID_ERROR_LIBOQS;
    }

    *signature_len = sm2_sig_der_len + mldsa_sig_len;
    *signature = (uint8_t*)malloc(*signature_len);
    if (!*signature) { free(sm2_sig_der); free(mldsa_sig); OQS_SIG_free(oqs); return HYBRID_ERROR_MALLOC; }
    memcpy(*signature, sm2_sig_der, sm2_sig_der_len);
    memcpy(*signature + sm2_sig_der_len, mldsa_sig, mldsa_sig_len);

    free(sm2_sig_der);
    free(mldsa_sig);
    OQS_SIG_free(oqs);
    return HYBRID_SUCCESS;
}

int hybrid_sig_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *public_key, size_t public_key_len
) {
    if (!signature || !message_digest || !public_key) return HYBRID_ERROR_PARAM;
    OQS_SIG *oqs = OQS_SIG_new(OQS_SIG_ALG);
    if (!oqs) return HYBRID_ERROR_LIBOQS;
    if (public_key_len != SM2_PUBKEY_LEN + oqs->length_public_key) { OQS_SIG_free(oqs); return HYBRID_ERROR_PARAM; }

    const uint8_t *sm2_pub = public_key;
    const uint8_t *mldsa_pub = public_key + SM2_PUBKEY_LEN;
    size_t mldsa_sig_len = oqs->length_signature;
    if (signature_len < mldsa_sig_len) { OQS_SIG_free(oqs); return HYBRID_ERROR_PARAM; }
    size_t sm2_sig_der_len = signature_len - mldsa_sig_len;
    const uint8_t *sm2_sig_der = signature;
    const uint8_t *mldsa_sig = signature + sm2_sig_der_len;

    // Verify SM2 (ECDSA over SM2 curve) DER
    int rc = sm2_verify_digest_der(message_digest, digest_len, sm2_pub, sm2_sig_der, sm2_sig_der_len);
    if (rc != HYBRID_SUCCESS) { OQS_SIG_free(oqs); return rc; }

    // Verify ML-DSA
    int v = OQS_SIG_verify(oqs, message_digest, digest_len, mldsa_sig, mldsa_sig_len, mldsa_pub);
    if (v != OQS_SUCCESS) { OQS_SIG_free(oqs); return HYBRID_ERROR_SIG_VERIFY; }
    OQS_SIG_free(oqs);
    return HYBRID_SUCCESS;
}


