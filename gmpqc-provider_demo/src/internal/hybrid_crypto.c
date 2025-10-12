#include "hybrid_crypto.h"

#include <string.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// 定义 SM2 封装的秘密长度
#define SM2_SHARED_SECRET_LEN 32

/**
 * @brief 生成混合密钥对。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_keygen(
    const char *kem_name,
    unsigned char **hybrid_pk,
    size_t *hybrid_pk_len,
    gmpqc_hybrid_secret_key_t **secret_key_out)
{
    gmpqc_crypto_ret_t ret = GMPQC_CRYPTO_ERROR;
    gmpqc_hybrid_secret_key_t *sk = NULL;
    unsigned char *pk_sm2_der = NULL;
    int pk_sm2_der_len = 0;
    uint8_t *pk_mlkem = NULL;

    sk = calloc(1, sizeof(gmpqc_hybrid_secret_key_t));
    if (sk == NULL) {
        return GMPQC_CRYPTO_MALLOC_ERROR;
    }

    sk->kem_ctx = OQS_KEM_new(kem_name);
    if (sk->kem_ctx == NULL) {
        ret = GMPQC_CRYPTO_OQS_ERROR;
        goto cleanup;
    }
    sk->kem_sk_len = sk->kem_ctx->length_secret_key;

    pk_mlkem = malloc(sk->kem_ctx->length_public_key);
    sk->kem_sk = malloc(sk->kem_sk_len);
    if (pk_mlkem == NULL || sk->kem_sk == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    if (OQS_KEM_keypair(sk->kem_ctx, pk_mlkem, sk->kem_sk) != OQS_SUCCESS) {
        ret = GMPQC_CRYPTO_OQS_ERROR;
        goto cleanup;
    }

    // 生成 SM2 密钥对（OpenSSL 3 EVP）
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (!kctx) { ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    if (EVP_PKEY_generate(kctx, &sk->sm2_key) <= 0) { EVP_PKEY_CTX_free(kctx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    EVP_PKEY_CTX_free(kctx);

    // 导出公钥为 SubjectPublicKeyInfo DER
    pk_sm2_der_len = i2d_PUBKEY(sk->sm2_key, &pk_sm2_der);
    if (pk_sm2_der_len <= 0) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }

    *hybrid_pk_len = 2 + pk_sm2_der_len + sk->kem_ctx->length_public_key;
    *hybrid_pk = malloc(*hybrid_pk_len);
    if (*hybrid_pk == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }

    (*hybrid_pk)[0] = (unsigned char)((pk_sm2_der_len >> 8) & 0xFF);
    (*hybrid_pk)[1] = (unsigned char)(pk_sm2_der_len & 0xFF);
    memcpy(*hybrid_pk + 2, pk_sm2_der, (size_t)pk_sm2_der_len);
    memcpy(*hybrid_pk + 2 + (size_t)pk_sm2_der_len, pk_mlkem, sk->kem_ctx->length_public_key);

    *secret_key_out = sk;
    sk = NULL;
    ret = GMPQC_CRYPTO_SUCCESS;

cleanup:
    OPENSSL_free(pk_sm2_der);
    free(pk_mlkem);
    if (sk != NULL) {
        gmpqc_hybrid_secret_key_free(sk);
    }
    if (ret != GMPQC_CRYPTO_SUCCESS) {
        free(*hybrid_pk);
        *hybrid_pk = NULL;
    }
    return ret;
}

/**
 * @brief 释放混合私钥结构体。
 */
void gmpqc_hybrid_secret_key_free(gmpqc_hybrid_secret_key_t *sk) {
    if (sk == NULL) {
        return;
    }
    if (sk->sm2_key) EVP_PKEY_free(sk->sm2_key);
    OQS_KEM_free(sk->kem_ctx);
    if (sk->kem_sk) {
        OQS_MEM_secure_free(sk->kem_sk, sk->kem_sk_len);
    }
    free(sk);
}

/**
 * @brief (客户端) 执行混合密钥封装操作。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_encaps(
    const char *kem_name,
    const unsigned char *hybrid_pk,
    size_t hybrid_pk_len,
    unsigned char **hybrid_ct,
    size_t *hybrid_ct_len,
    unsigned char **shared_secret,
    size_t *shared_secret_len)
{
    gmpqc_crypto_ret_t ret = GMPQC_CRYPTO_ERROR;
    const unsigned char *p_sm2_pk = NULL, *p_mlkem_pk = NULL;
    size_t sm2_pk_len = 0;
    size_t mlkem_pk_len = 0;
    EVP_PKEY *sm2_pub = NULL;

    OQS_KEM *kem = NULL;
    uint8_t *s_sm2 = NULL, *c_sm2 = NULL, *s_mlkem = NULL, *c_mlkem = NULL;
    size_t c_sm2_len = 0;

    if (hybrid_pk_len < 2) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    sm2_pk_len = ((size_t)hybrid_pk[0] << 8) | (size_t)hybrid_pk[1];
    p_sm2_pk = hybrid_pk + 2;
    p_mlkem_pk = p_sm2_pk + sm2_pk_len;
    if (2 + sm2_pk_len > hybrid_pk_len) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    mlkem_pk_len = hybrid_pk_len - 2 - sm2_pk_len;
    
    kem = OQS_KEM_new(kem_name);
    if (kem == NULL) {
        return GMPQC_CRYPTO_OQS_ERROR;
    }
    if (mlkem_pk_len != kem->length_public_key) {
        ret = GMPQC_CRYPTO_INVALID_INPUT_ERROR;
        goto cleanup;
    }

    // 从 DER 解析 SM2 公钥（OpenSSL EVP）
    {
        const unsigned char *tmp = p_sm2_pk;
        sm2_pub = d2i_PUBKEY(NULL, &tmp, (long)sm2_pk_len);
        if (!sm2_pub) { ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    }

    s_sm2 = malloc(SM2_SHARED_SECRET_LEN);
    if (s_sm2 == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    if (RAND_bytes(s_sm2, SM2_SHARED_SECRET_LEN) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }

    c_sm2 = NULL; // will be allocated after querying size
    // SM2 公钥加密（EVP）
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(sm2_pub, NULL);
    if (!ectx) { ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    if (EVP_PKEY_encrypt_init(ectx) <= 0) { EVP_PKEY_CTX_free(ectx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    // 可选：设置 SM2 ID（双方需一致）。如需设置，可启用以下代码：
    // const char *sm2_id = "1234567812345678"; OSSL_PARAM params[] = {
    //   OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DIST_ID, (void*)sm2_id, strlen(sm2_id)), OSSL_PARAM_END };
    // EVP_PKEY_CTX_set_params(ectx, params);
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ectx, NULL, &outlen, s_sm2, SM2_SHARED_SECRET_LEN) <= 0) { EVP_PKEY_CTX_free(ectx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    c_sm2 = malloc(outlen);
    if (!c_sm2) { EVP_PKEY_CTX_free(ectx); ret = GMPQC_CRYPTO_MALLOC_ERROR; goto cleanup; }
    c_sm2_len = outlen;
    if (EVP_PKEY_encrypt(ectx, c_sm2, &c_sm2_len, s_sm2, SM2_SHARED_SECRET_LEN) <= 0) { EVP_PKEY_CTX_free(ectx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    EVP_PKEY_CTX_free(ectx);

    s_mlkem = malloc(kem->length_shared_secret);
    c_mlkem = malloc(kem->length_ciphertext);
    if (s_mlkem == NULL || c_mlkem == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    if (OQS_KEM_encaps(kem, c_mlkem, s_mlkem, p_mlkem_pk) != OQS_SUCCESS) {
        ret = GMPQC_CRYPTO_OQS_ERROR;
        goto cleanup;
    }

    *hybrid_ct_len = 2 + c_sm2_len + kem->length_ciphertext;
    *hybrid_ct = malloc(*hybrid_ct_len);
    if (*hybrid_ct == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    (*hybrid_ct)[0] = (unsigned char)((c_sm2_len >> 8) & 0xFF);
    (*hybrid_ct)[1] = (unsigned char)(c_sm2_len & 0xFF);
    memcpy(*hybrid_ct + 2, c_sm2, c_sm2_len);
    memcpy(*hybrid_ct + 2 + c_sm2_len, c_mlkem, kem->length_ciphertext);
    
    *shared_secret_len = SM2_SHARED_SECRET_LEN + kem->length_shared_secret;
    *shared_secret = malloc(*shared_secret_len);
    if (*shared_secret == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    memcpy(*shared_secret, s_sm2, SM2_SHARED_SECRET_LEN);
    memcpy(*shared_secret + SM2_SHARED_SECRET_LEN, s_mlkem, kem->length_shared_secret);

    ret = GMPQC_CRYPTO_SUCCESS;

cleanup:
    if (sm2_pub) EVP_PKEY_free(sm2_pub);
    OQS_KEM_free(kem);
    free(s_sm2);
    free(c_sm2);
    free(s_mlkem);
    free(c_mlkem);
    if (ret != GMPQC_CRYPTO_SUCCESS) {
        free(*hybrid_ct);
        *hybrid_ct = NULL;
        free(*shared_secret);
        *shared_secret = NULL;
    }
    return ret;
}

/**
 * @brief (服务器端) 执行混合密钥解封装操作。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_decaps(
    const gmpqc_hybrid_secret_key_t *secret_key,
    const unsigned char *hybrid_ct,
    size_t hybrid_ct_len,
    unsigned char **shared_secret,
    size_t *shared_secret_len)
{
    gmpqc_crypto_ret_t ret = GMPQC_CRYPTO_ERROR;
    const uint8_t *p_sm2_ct = NULL, *p_mlkem_ct = NULL;
    size_t sm2_ct_len = 0;
    size_t mlkem_ct_len = 0;
    uint8_t *s_sm2 = NULL, *s_mlkem = NULL;
    size_t s_sm2_len_out = 0;
    
    if (secret_key == NULL || secret_key->kem_ctx == NULL || secret_key->kem_sk == NULL) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }

    if (hybrid_ct_len < 2) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    sm2_ct_len = ((size_t)hybrid_ct[0] << 8) | (size_t)hybrid_ct[1];
    p_sm2_ct = hybrid_ct + 2;
    p_mlkem_ct = p_sm2_ct + sm2_ct_len;
    if (2 + sm2_ct_len > hybrid_ct_len) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    mlkem_ct_len = hybrid_ct_len - 2 - sm2_ct_len;
    if (mlkem_ct_len != secret_key->kem_ctx->length_ciphertext) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }

    s_sm2 = NULL; // allocated after size query
    // SM2 私钥解密（EVP）
    if (!secret_key->sm2_key) { ret = GMPQC_CRYPTO_INVALID_INPUT_ERROR; goto cleanup; }
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(secret_key->sm2_key, NULL);
    if (!dctx) { ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    if (EVP_PKEY_decrypt_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    size_t ptlen = 0;
    if (EVP_PKEY_decrypt(dctx, NULL, &ptlen, p_sm2_ct, sm2_ct_len) <= 0) { EVP_PKEY_CTX_free(dctx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    s_sm2 = malloc(ptlen);
    if (!s_sm2) { EVP_PKEY_CTX_free(dctx); ret = GMPQC_CRYPTO_MALLOC_ERROR; goto cleanup; }
    s_sm2_len_out = ptlen;
    if (EVP_PKEY_decrypt(dctx, s_sm2, &s_sm2_len_out, p_sm2_ct, sm2_ct_len) <= 0) { EVP_PKEY_CTX_free(dctx); ret = GMPQC_CRYPTO_GMSSL_ERROR; goto cleanup; }
    EVP_PKEY_CTX_free(dctx);
    if (s_sm2_len_out != SM2_SHARED_SECRET_LEN) { ret = GMPQC_CRYPTO_ERROR; goto cleanup; }

    s_mlkem = malloc(secret_key->kem_ctx->length_shared_secret);
    if (s_mlkem == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    if (OQS_KEM_decaps(secret_key->kem_ctx, s_mlkem, p_mlkem_ct, secret_key->kem_sk) != OQS_SUCCESS) {
        ret = GMPQC_CRYPTO_OQS_ERROR;
        goto cleanup;
    }

    *shared_secret_len = SM2_SHARED_SECRET_LEN + secret_key->kem_ctx->length_shared_secret;
    *shared_secret = malloc(*shared_secret_len);
    if (*shared_secret == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    memcpy(*shared_secret, s_sm2, SM2_SHARED_SECRET_LEN);
    memcpy(*shared_secret + SM2_SHARED_SECRET_LEN, s_mlkem, secret_key->kem_ctx->length_shared_secret);
    
    ret = GMPQC_CRYPTO_SUCCESS;

cleanup:
    free(s_sm2);
    free(s_mlkem);
    if (ret != GMPQC_CRYPTO_SUCCESS) {
        free(*shared_secret);
        *shared_secret = NULL;
    }
    return ret;
}