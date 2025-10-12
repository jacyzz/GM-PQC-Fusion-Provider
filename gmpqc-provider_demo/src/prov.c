#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

/*
 * 声明我们将要引用的外部函数分发表。
 * 这个 'gmpqc_hybrid_kem_functions' 数组是在 src/hybrid_kem.c 中定义的。
 * 'extern' 关键字告诉编译器，这个变量的实体在别的文件里，链接时再去找它。
 */
extern const OSSL_DISPATCH gmpqc_hybrid_kem_functions[];

/*
 * 定义我们的 Provider 所支持的算法列表。
 * 目前，我们只支持一种 KEM 算法。
 */
static const OSSL_ALGORITHM gmpqc_supported_kems[] = {
    /*
     * 每一项都定义了一个算法:
     * 1. 算法名称 (provider-native name): "SM2-ML-KEM-768"
     * 这是我们的算法在 Provider 内部的官方名称。
     *
     * 2. 属性字符串 (property string): "provider=gmpqc"
     * 这定义了一个属性，方便应用程序在有多个 Provider 提供同名算法时进行选择。
     *
     * 3. 实现 (implementation): gmpqc_hybrid_kem_functions
     * 这是最关键的部分，它将算法名称与我们在 hybrid_kem.c 中定义的函数实现关联起来。
     */
    { "SM2-ML-KEM-768", "provider=gmpqc", gmpqc_hybrid_kem_functions },

    /* 数组必须以 {NULL, NULL, NULL} 结尾 */
    { NULL, NULL, NULL }
};

/*
 * 实现 Provider 的 "查询" 功能。
 * 当 OpenSSL 想知道我们的 Provider 支持哪些类型的操作时，就会调用这个函数。
 */
static const OSSL_ALGORITHM *gmpqc_query(void *provctx, int operation_id, int *no_cache) {
    // operation_id 是 OpenSSL 定义的操作类型 ID。
    // 我们只关心对 KEM (Key Encapsulation Mechanism) 操作的查询。
    if (operation_id == OSSL_OP_KEM) {
        // 如果 OpenSSL 在询问 "你支持哪些 KEM 算法？"
        // 我们就返回上面定义的 KEM 算法列表。
        return gmpqc_supported_kems;
    }

    // 对于其他类型的操作 (如 Cipher, Signature 等)，我们返回 NULL，表示不支持。
    return NULL;
}

/*
 * 实现 Provider 的核心功能分发表。
 * 这定义了 Provider 自身的核心行为，比如如何响应查询。
 */
static const OSSL_DISPATCH gmpqc_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))gmpqc_query },
    { 0, NULL }
};

/*
 * ===================================================================================
 * Provider 的主入口函数
 * ===================================================================================
 * 这是整个 Provider 库的唯一入口点。当 OpenSSL 通过 dlopen() 加载我们的 .so 文件时，
 * 它会查找并调用这个名为 OSSL_provider_init 的函数。
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                     const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out,
                     void **provctx) {
    /*
     * in:  一个由 OpenSSL 核心传入的函数指针数组，让我们可以调用 OpenSSL 的核心功能。
     * out: 一个需要我们传出的函数指针数组，告诉 OpenSSL 如何调用我们的 Provider。
     * provctx: 一个指向我们 Provider 全局上下文的指针，我们可以在这里存储全局状态。
     */

    // 我们将上面定义的 Provider 核心功能分发表传出给 OpenSSL。
    *out = gmpqc_provider_functions;

    // 我们没有需要初始化的全局状态，所以将 provctx 设为 NULL。
    *provctx = NULL;

    // 返回 1 表示初始化成功。
    return 1;
}