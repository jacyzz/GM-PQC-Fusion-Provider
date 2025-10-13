#include "hybrid_crypto.h"

#include <string.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
// 【修正】: 只需要 sm2.h 就够了，它包含了所有需要的函数声明
#include <gmssl/sm2.h>

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
    size_t pk_sm2_der_len = 0;
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

    // 【修正】: 使用新的、正确的 GmSSL API 生成 SM2 密钥
    if (sm2_key_generate(&sk->sm2_key) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }

    // 【修正】: 使用新的、正确的 GmSSL API 序列化公钥
    if (sm2_public_key_info_to_der(&sk->sm2_key, &pk_sm2_der, &pk_sm2_der_len) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }

    *hybrid_pk_len = 2 + pk_sm2_der_len + sk->kem_ctx->length_public_key;
    *hybrid_pk = malloc(*hybrid_pk_len);
    if (*hybrid_pk == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }

    *(uint16_t*)*hybrid_pk = htons(pk_sm2_der_len);
    memcpy(*hybrid_pk + 2, pk_sm2_der, pk_sm2_der_len);
    memcpy(*hybrid_pk + 2 + pk_sm2_der_len, pk_mlkem, sk->kem_ctx->length_public_key);

    *secret_key_out = sk;
    sk = NULL;
    ret = GMPQC_CRYPTO_SUCCESS;

cleanup:
    free(pk_sm2_der); // GmSSL 的 to_der 函数会分配内存，需要释放
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
    // 【修正】: SM2_KEY 是值类型，不需要 free。
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
    SM2_KEY sm2_pk_obj = {0};

    OQS_KEM *kem = NULL;
    uint8_t *s_sm2 = NULL, *c_sm2 = NULL, *s_mlkem = NULL, *c_mlkem = NULL;
    size_t c_sm2_len = 0;

    if (hybrid_pk_len < 2) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    sm2_pk_len = ntohs(*(uint16_t*)hybrid_pk);
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

    // 【修正】: 使用新的、正确的 GmSSL API 解析公钥
    if (sm2_public_key_info_from_der(&sm2_pk_obj, &p_sm2_pk, &sm2_pk_len) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
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

    c_sm2 = malloc(SM2_MAX_CIPHERTEXT_SIZE);
    if (c_sm2 == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }
    c_sm2_len = SM2_MAX_CIPHERTEXT_SIZE;

    // 【修正】: 调用新的、正确的 sm2_encrypt 函数
    if (sm2_encrypt(&sm2_pk_obj, s_sm2, SM2_SHARED_SECRET_LEN, c_sm2, &c_sm2_len) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }

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
    *(uint16_t*)*hybrid_ct = htons(c_sm2_len);
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
    // 【修正】: SM2_KEY 是栈变量，不需要清理
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
    sm2_ct_len = ntohs(*(uint16_t*)hybrid_ct);
    p_sm2_ct = hybrid_ct + 2;
    p_mlkem_ct = p_sm2_ct + sm2_ct_len;
    if (2 + sm2_ct_len > hybrid_ct_len) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }
    mlkem_ct_len = hybrid_ct_len - 2 - sm2_ct_len;
    if (mlkem_ct_len != secret_key->kem_ctx->length_ciphertext) {
        return GMPQC_CRYPTO_INVALID_INPUT_ERROR;
    }

    s_sm2 = malloc(SM2_MAX_PLAINTEXT_SIZE); // 分配足够大的空间
    if (s_sm2 == NULL) {
        ret = GMPQC_CRYPTO_MALLOC_ERROR;
        goto cleanup;
    }

    // 【修正】: 调用新的、正确的 sm2_decrypt 函数
    if (sm2_decrypt(&secret_key->sm2_key, p_sm2_ct, sm2_ct_len, s_sm2, &s_sm2_len_out) != 1) {
        ret = GMPQC_CRYPTO_GMSSL_ERROR;
        goto cleanup;
    }
    if (s_sm2_len_out != SM2_SHARED_SECRET_LEN) {
        ret = GMPQC_CRYPTO_ERROR;
        goto cleanup;
    }

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