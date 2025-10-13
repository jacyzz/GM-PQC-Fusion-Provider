#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/hybrid_crypto.h" // 包含我们自己的底层加密模块
#include "internal/gmpqc_keymgmt.h"
#include <string.h>

// 定义我们将在 Provider 中注册的 KEM 算法的名称
#define HYBRID_KEM_NAME GMPQC_HYBRID_KEM_NAME

// --- 步骤 1: 定义 Provider 的上下文结构体 ---
// 这个结构体用于在 KEM 操作的不同阶段之间传递数据。
typedef struct {
    // libprov_ctx 是 OpenSSL provider 框架要求的一部分
    void *libprov_ctx;

    // 我们自己的混合私钥，在解封装时使用
    gmpqc_hybrid_secret_key_t *hybrid_sk;

    // 对方的混合公钥，在封装时使用
    unsigned char *peer_hybrid_pk;
    size_t peer_hybrid_pk_len;

} GMPQC_KEM_CTX;


// --- 步骤 2: 实现 OpenSSL 要求的所有 KEM 接口函数 ---

// 创建并返回一个新的 KEM 上下文
static void *gmpqc_kem_newctx(void *provctx) {
    GMPQC_KEM_CTX *ctx = calloc(1, sizeof(GMPQC_KEM_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libprov_ctx = provctx;
    return ctx;
}

// 释放 KEM 上下文
static void gmpqc_kem_freectx(void *vctx) {
    GMPQC_KEM_CTX *ctx = (GMPQC_KEM_CTX *)vctx;
    if (ctx == NULL) {
        return;
    }
    // 释放我们自己分配的资源
    gmpqc_hybrid_secret_key_free(ctx->hybrid_sk);
    free(ctx->peer_hybrid_pk);
    free(ctx);
}

// 复制一个 KEM 上下文
static void *gmpqc_kem_dupctx(void *vctx) {
    GMPQC_KEM_CTX *src_ctx = (GMPQC_KEM_CTX *)vctx;
    GMPQC_KEM_CTX *dst_ctx = NULL;

    dst_ctx = gmpqc_kem_newctx(src_ctx->libprov_ctx);
    if (dst_ctx == NULL) {
        return NULL;
    }

    // TODO: 实现复制逻辑，例如复制密钥等
    // 如果 src_ctx->hybrid_sk 存在，需要编写一个 gmpqc_hybrid_secret_key_dup() 函数
    // 如果 src_ctx->peer_hybrid_pk 存在，需要复制它

    return dst_ctx;
}


// (服务器端) 初始化解封装操作，通常在这里加载私钥
static int gmpqc_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    GMPQC_KEM_CTX *ctx = (GMPQC_KEM_CTX *)vctx;
    (void)params;
    /* vkey is provider-side key (KEYMGMT). We clone materials for decap. */
    if (!vkey) return 0;
    if (ctx->hybrid_sk) { gmpqc_hybrid_secret_key_free(ctx->hybrid_sk); ctx->hybrid_sk = NULL; }
    if (!gmpqc_keymgmt_clone_for_decap((GMPQC_KEY*)vkey, &ctx->hybrid_sk)) return 0;
    return 1; // 成功
}

// (服务器端) 执行解封装
static int gmpqc_kem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                               const unsigned char *in, size_t inlen) {
    GMPQC_KEM_CTX *ctx = (GMPQC_KEM_CTX *)vctx;
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;
    
    // 调用我们的底层解封装函数
    if (gmpqc_hybrid_decaps(ctx->hybrid_sk, in, inlen, &shared_secret, &shared_secret_len) != GMPQC_CRYPTO_SUCCESS) {
        return 0; // 失败
    }
    
    // 将结果复制到 OpenSSL 提供的 out 缓冲区
    if (out != NULL) {
        memcpy(out, shared_secret, shared_secret_len);
    }
    *outlen = shared_secret_len;
    
    free(shared_secret);
    return 1; // 成功
}


// (客户端) 初始化封装操作，通常在这里加载公钥
static int gmpqc_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    GMPQC_KEM_CTX *ctx = (GMPQC_KEM_CTX *)vctx;
    (void)params;
    if (ctx->peer_hybrid_pk) { OPENSSL_free(ctx->peer_hybrid_pk); ctx->peer_hybrid_pk = NULL; ctx->peer_hybrid_pk_len = 0; }
    if (!vkey) return 0;
    if (!gmpqc_keymgmt_get_serialized_pub((GMPQC_KEY*)vkey, &ctx->peer_hybrid_pk, &ctx->peer_hybrid_pk_len)) return 0;
    return 1; // 成功
}

// (客户端) 执行封装
static int gmpqc_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                               unsigned char *secret, size_t *secretlen) {
    GMPQC_KEM_CTX *ctx = (GMPQC_KEM_CTX *)vctx;
    unsigned char *hybrid_ct = NULL;
    size_t hybrid_ct_len = 0;
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;

    // 调用我们的底层封装函数
    /* Use the underlying OQS KEM for liboqs (e.g., "ML-KEM-768"), not the provider algorithm name */
    if (gmpqc_hybrid_encaps(GMPQC_UNDERLYING_OQS_KEM, ctx->peer_hybrid_pk, ctx->peer_hybrid_pk_len, &hybrid_ct, &hybrid_ct_len, &shared_secret, &shared_secret_len) != GMPQC_CRYPTO_SUCCESS) {
        return 0; // 失败
    }

    // OpenSSL KEM 接口要求两个输出：
    // out:  封装后的密文 (ciphertext)
    // secret: 协商出的共享密钥 (shared secret)
    
    if (out != NULL) {
        memcpy(out, hybrid_ct, hybrid_ct_len);
    }
    *outlen = hybrid_ct_len;
    
    if (secret != NULL) {
        memcpy(secret, shared_secret, shared_secret_len);
    }
    *secretlen = shared_secret_len;

    free(hybrid_ct);
    free(shared_secret);
    return 1; // 成功
}


// --- 步骤 3: 创建函数分发表 (Dispatch Table) ---
// 这个数组是 "翻译" 的核心，它告诉 OpenSSL 每个标准操作应该调用我们哪个函数。
const OSSL_DISPATCH gmpqc_hybrid_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))gmpqc_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))gmpqc_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))gmpqc_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))gmpqc_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))gmpqc_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))gmpqc_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))gmpqc_kem_decapsulate },
    { 0, NULL } // 数组以 {0, NULL} 结尾
};