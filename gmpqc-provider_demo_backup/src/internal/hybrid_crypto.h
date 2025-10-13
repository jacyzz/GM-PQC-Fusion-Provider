#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
// 【修正】: 引入 gmssl/sm2.h 因为 SM2_KEY 在此定义
#include <gmssl/sm2.h>
#include <oqs/oqs.h>

/*
 =================================================================================
 * 序列化格式定义 (Serialization Format Definition)
 =================================================================================
 * 为了确保不同端点之间的互操作性，我们定义如下的字节流格式。
 * 所有多字节整数均使用网络字节序 (Big-Endian)。
 *
 * 1. 混合公钥 (Hybrid Public Key)
 * 格式: [SM2_PK_LEN (2 bytes)] [SM2_PK_DATA] [MLKEM_PK_DATA]
 * - SM2_PK_LEN:    一个 uint16_t 整数，表示后面 SM2 公钥的字节长度。
 * - SM2_PK_DATA:   SM2 公钥的标准 DER 编码字节流。
 * - MLKEM_PK_DATA: ML-KEM 公钥的原始字节流。其长度由 `hybrid_pk_len - 2 - SM2_PK_LEN` 得出。
 *
 * 2. 混合密文 (Hybrid Ciphertext)
 * 格式: [SM2_CT_LEN (2 bytes)] [SM2_CT_DATA] [MLKEM_CT_DATA]
 * - SM2_CT_LEN:    一个 uint16_t 整数，表示后面 SM2 密文的字节长度。
 * - SM2_CT_DATA:   SM2 密文的标准 DER 编码字节流。
 * - MLKEM_CT_DATA: ML-KEM 密文的原始字节流。其长度由 `hybrid_ct_len - 2 - SM2_CT_LEN` 得出。
 *
 =================================================================================
*/


/**
 * @brief 定义详细的函数返回错误码
 */
typedef enum {
    GMPQC_CRYPTO_SUCCESS = 1,                 // 操作成功
    GMPQC_CRYPTO_ERROR = 0,                   // 通用/未知错误
    GMPQC_CRYPTO_MALLOC_ERROR = -1,           // 内存分配失败
    GMPQC_CRYPTO_OQS_ERROR = -2,              // liboqs 库函数调用失败
    GMPQC_CRYPTO_GMSSL_ERROR = -3,            // GmSSL/OpenSSL 库函数调用失败
    GMPQC_CRYPTO_INVALID_INPUT_ERROR = -4,    // 输入参数无效或解析失败
} gmpqc_crypto_ret_t;


/**
 * @brief 【重大修正】: 使用 SM2_KEY 值类型代替 EC_KEY 指针
 */
typedef struct {
    SM2_KEY sm2_key;      // SM2 密钥对 (值类型，不再是指针)
    OQS_KEM *kem_ctx;     // OQS KEM 上下文 (包含算法详情和函数指针)
    uint8_t *kem_sk;      // OQS KEM 私钥的原始字节
    size_t kem_sk_len;    // OQS KEM 私钥的长度
} gmpqc_hybrid_secret_key_t;


/**
 * @brief 生成混合密钥对。
 *
 * @param[in]  kem_name              要使用的 OQS KEM 算法名称 (例如, "ML-KEM-768")。
 * @param[out] hybrid_pk             按照约定格式序列化后的混合公钥，调用者需负责释放内存。
 * @param[out] hybrid_pk_len         混合公钥的长度。
 * @param[out] secret_key_out        生成的混合私钥结构体，调用者需使用 gmpqc_hybrid_secret_key_free() 释放。
 * @return                           返回 gmpqc_crypto_ret_t 错误码。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_keygen(
    const char *kem_name,
    unsigned char **hybrid_pk,
    size_t *hybrid_pk_len,
    gmpqc_hybrid_secret_key_t **secret_key_out
);

/**
 * @brief 释放由 gmpqc_hybrid_keygen 创建的混合私钥结构体。
 *
 * @param[in] sk 要释放的私钥结构体。
 */
void gmpqc_hybrid_secret_key_free(gmpqc_hybrid_secret_key_t *sk);

/**
 * @brief (客户端) 执行混合密钥封装操作。
 *
 * @param[in]  kem_name              要使用的 OQS KEM 算法名称。
 * @param[in]  hybrid_pk             从服务器获取的、序列化后的混合公钥。
 * @param[in]  hybrid_pk_len         混合公钥的长度。
 * @param[out] hybrid_ct             封装后生成的、序列化后的混合密文，调用者需负责释放。
 * @param[out] hybrid_ct_len         混合密文的长度。
 * @param[out] shared_secret         最终的共享密钥 (S_SM2 || S_MLKEM)，调用者需负责释放。
 * @param[out] shared_secret_len     最终共享密钥的长度。
 * @return                           返回 gmpqc_crypto_ret_t 错误码。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_encaps(
    const char *kem_name,
    const unsigned char *hybrid_pk,
    size_t hybrid_pk_len,
    unsigned char **hybrid_ct,
    size_t *hybrid_ct_len,
    unsigned char **shared_secret,
    size_t *shared_secret_len
);

/**
 * @brief (服务器端) 执行混合密钥解封装操作。
 *
 * @param[in]  secret_key            服务器自己的混合私钥。
 * @param[in]  hybrid_ct             从客户端收到的、序列化后的混合密文。
 * @param[in]  hybrid_ct_len         混合密文的长度。
 * @param[out] shared_secret         恢复出的最终共享密钥，调用者需负责释放。
 * @param[out] shared_secret_len     最终共享密钥的长度。
 * @return                           返回 gmpqc_crypto_ret_t 错误码。
 */
gmpqc_crypto_ret_t gmpqc_hybrid_decaps(
    const gmpqc_hybrid_secret_key_t *secret_key,
    const unsigned char *hybrid_ct,
    size_t hybrid_ct_len,
    unsigned char **shared_secret,
    size_t *shared_secret_len
);


#endif // HYBRID_CRYPTO_H