#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdlib.h>
#include "internal/gmpqc_keymgmt.h"

struct gmpqc_key_st {
    EVP_PKEY *sm2;                 /* private (server) or public (client) */
    OQS_KEM  *oqs;
    unsigned char *oqs_pk; size_t oqs_pk_len;
    unsigned char *oqs_sk; size_t oqs_sk_len; /* only on server */
};

static void *gmpqc_keymgmt_new(void *provctx) {
    (void)provctx; 
    GMPQC_KEY *k = OPENSSL_zalloc(sizeof(*k));
    return k;
}
static void gmpqc_keymgmt_free(void *vkey) {
    GMPQC_KEY *k = vkey; if (!k) return;
    if (k->sm2) EVP_PKEY_free(k->sm2);
    if (k->oqs) OQS_KEM_free(k->oqs);
    OPENSSL_free(k->oqs_pk);
    if (k->oqs_sk) OQS_MEM_secure_free(k->oqs_sk, k->oqs_sk_len);
    OPENSSL_free(k);
}

static int gmpqc_keymgmt_has(const void *vkey, int selection) {
    const GMPQC_KEY *k = vkey; if (!k) return 0;
    int have_pub = (k->sm2 && k->oqs_pk && k->oqs_pk_len>0);
    int have_priv = (k->sm2 && k->oqs_sk && k->oqs_sk_len>0);
    int ok = 1;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) ok &= have_pub;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ok &= have_priv;
    return ok;
}

/* Generate SM2 key + OQS ML-KEM-768 keypair */
static void *gmpqc_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) {
    (void)cb; (void)cbarg; (void)genctx;
    GMPQC_KEY *k = gmpqc_keymgmt_new(NULL);
    if (!k) return NULL;
    /* SM2 */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (!kctx) goto err;
    if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); goto err; }
    if (EVP_PKEY_generate(kctx, &k->sm2) <= 0) { EVP_PKEY_CTX_free(kctx); goto err; }
    EVP_PKEY_CTX_free(kctx);
    /* OQS */
    k->oqs = OQS_KEM_new(GMPQC_UNDERLYING_OQS_KEM);
    if (!k->oqs) goto err;
    k->oqs_pk_len = k->oqs->length_public_key;
    k->oqs_sk_len = k->oqs->length_secret_key;
    k->oqs_pk = OPENSSL_malloc(k->oqs_pk_len);
    k->oqs_sk = OPENSSL_malloc(k->oqs_sk_len);
    if (!k->oqs_pk || !k->oqs_sk) goto err;
    if (OQS_KEM_keypair(k->oqs, k->oqs_pk, k->oqs_sk) != OQS_SUCCESS) goto err;
    return k;
err:
    gmpqc_keymgmt_free(k);
    return NULL;
}

static void *gmpqc_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) {
    (void)provctx; (void)selection; (void)params; return (void*)1; /* opaque token */
}

static void gmpqc_keymgmt_gen_cleanup(void *genctx) {
    (void)genctx; /* nothing to cleanup in our trivial ctx */
}

/* Public key import: OSSL_PKEY_PARAM_PUB_KEY carries serialized [2B|DER|OQS pk] */
static int gmpqc_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[]) {
    GMPQC_KEY *k = vkey; if (!k) return 0;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!p || !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) return 0;
    const unsigned char *in = NULL; size_t inlen = 0;
    if (OSSL_PARAM_get_octet_string_ptr(p, (const void**)&in, &inlen) <= 0) return 0;
    if (inlen < 2) return 0;
    size_t sm2_der_len = ((size_t)in[0] << 8) | (size_t)in[1];
    if (2 + sm2_der_len > inlen) return 0;
    const unsigned char *der = in + 2; const unsigned char *oqs_pk = der + sm2_der_len;
    size_t oqs_pk_len = inlen - 2 - sm2_der_len;
    /* parse SM2 pubkey */
    const unsigned char *tmp = der;
    EVP_PKEY *sm2 = d2i_PUBKEY(NULL, &tmp, (long)sm2_der_len);
    if (!sm2) return 0;
    /* store */
    k->sm2 = sm2;
    k->oqs = OQS_KEM_new(GMPQC_UNDERLYING_OQS_KEM);
    if (!k->oqs) return 0;
    if (oqs_pk_len != k->oqs->length_public_key) return 0;
    k->oqs_pk_len = oqs_pk_len;
    k->oqs_pk = OPENSSL_malloc(oqs_pk_len);
    if (!k->oqs_pk) return 0;
    memcpy(k->oqs_pk, oqs_pk, oqs_pk_len);
    return 1;
}

static const OSSL_PARAM *gmpqc_keymgmt_import_types(int selection) {
    static const OSSL_PARAM types_pub[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) return types_pub;
    return NULL;
}

static int gmpqc_keymgmt_export(void *vkey, int selection, OSSL_CALLBACK *cb, void *cbarg) {
    GMPQC_KEY *k = vkey; if (!k) return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) return 0;
    unsigned char *spki = NULL; int spki_len = i2d_PUBKEY(k->sm2, &spki);
    if (spki_len <= 0) return 0;
    size_t outlen = 2 + (size_t)spki_len + k->oqs_pk_len;
    unsigned char *buf = OPENSSL_malloc(outlen);
    if (!buf) { OPENSSL_free(spki); return 0; }
    buf[0] = (unsigned char)((spki_len >> 8) & 0xFF);
    buf[1] = (unsigned char)(spki_len & 0xFF);
    memcpy(buf + 2, spki, (size_t)spki_len);
    memcpy(buf + 2 + (size_t)spki_len, k->oqs_pk, k->oqs_pk_len);
    OPENSSL_free(spki);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, buf, outlen);
    params[1] = OSSL_PARAM_construct_end();
    int ok = cb(params, cbarg);
    OPENSSL_free(buf);
    return ok;
}

static const OSSL_PARAM *gmpqc_keymgmt_export_types(int selection) {
    static const OSSL_PARAM types_pub[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) return types_pub;
    return NULL;
}

/* Optional: gettable/get params for keys (we return nothing specific, but satisfy API) */
static const OSSL_PARAM *gmpqc_keymgmt_gettable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM params[] = {
        /* Allow querying the serialized hybrid public key via standard name */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}
static int gmpqc_keymgmt_get_params(void *vkey, OSSL_PARAM params[]) {
    GMPQC_KEY *k = vkey; if (!k || !params) return 0;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        unsigned char *buf = NULL; size_t len = 0;
        if (!gmpqc_keymgmt_get_serialized_pub(k, &buf, &len))
            return 0;
        /* Two-phase: if no buffer, just report needed size */
        if (p->data == NULL || p->data_size == 0) {
            p->return_size = len;
            OPENSSL_free(buf);
            return 1;
        }
        if (p->data_size < len) {
            p->return_size = len;
            OPENSSL_free(buf);
            return 0;
        }
        memcpy(p->data, buf, len);
        p->return_size = len;
        OPENSSL_free(buf);
    }
    return 1;
}

static const OSSL_PARAM *gmpqc_keymgmt_settable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}
static int gmpqc_keymgmt_set_params(void *vkey, const OSSL_PARAM params[]) {
    (void)vkey; (void)params; return 1;
}

/* Map supported operations to algorithm name; needed by some EVP paths */
static const char *gmpqc_keymgmt_query_operation_name(int operation_id) {
    if (operation_id == OSSL_OP_KEM)
        return GMPQC_HYBRID_KEM_NAME;
    return NULL;
}

/* glue for KEM */
int gmpqc_keymgmt_get_serialized_pub(GMPQC_KEY *k, unsigned char **out, size_t *outlen) {
    if (!k || !out || !outlen) return 0;
    unsigned char *spki = NULL; int spki_len = i2d_PUBKEY(k->sm2, &spki);
    if (spki_len <= 0) return 0;
    size_t len = 2 + (size_t)spki_len + k->oqs_pk_len;
    unsigned char *buf = OPENSSL_malloc(len);
    if (!buf) { OPENSSL_free(spki); return 0; }
    buf[0] = (unsigned char)((spki_len >> 8) & 0xFF);
    buf[1] = (unsigned char)(spki_len & 0xFF);
    memcpy(buf + 2, spki, (size_t)spki_len);
    memcpy(buf + 2 + (size_t)spki_len, k->oqs_pk, k->oqs_pk_len);
    OPENSSL_free(spki);
    *out = buf; *outlen = len; return 1;
}

int gmpqc_keymgmt_clone_for_decap(GMPQC_KEY *k, gmpqc_hybrid_secret_key_t **out_sk) {
    if (!k || !out_sk) return 0;
    gmpqc_hybrid_secret_key_t *sk = OPENSSL_zalloc(sizeof(*sk));
    if (!sk) return 0;
    sk->sm2_key = k->sm2 ? EVP_PKEY_dup(k->sm2) : NULL;
    sk->kem_ctx = k->oqs ? OQS_KEM_new(GMPQC_UNDERLYING_OQS_KEM) : NULL;
    if (!sk->sm2_key || !sk->kem_ctx) { gmpqc_hybrid_secret_key_free(sk); return 0; }
    if (!k->oqs_sk || !k->oqs_sk_len) { gmpqc_hybrid_secret_key_free(sk); return 0; }
    sk->kem_sk_len = k->oqs_sk_len;
    sk->kem_sk = OPENSSL_malloc(sk->kem_sk_len);
    if (!sk->kem_sk) { gmpqc_hybrid_secret_key_free(sk); return 0; }
    memcpy(sk->kem_sk, k->oqs_sk, sk->kem_sk_len);
    *out_sk = sk; return 1;
}

/* ============== dispatch table & query glue ============== */
static const OSSL_DISPATCH gmpqc_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))gmpqc_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gmpqc_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gmpqc_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))gmpqc_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gmpqc_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gmpqc_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gmpqc_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gmpqc_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gmpqc_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gmpqc_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))gmpqc_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))gmpqc_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))gmpqc_keymgmt_settable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))gmpqc_keymgmt_set_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))gmpqc_keymgmt_query_operation_name },
    { 0, NULL }
};

/* expose algorithm list for prov.c */
typedef struct { const char *algorithm; const char *property; const OSSL_DISPATCH *impl; } ALGROW;
const OSSL_ALGORITHM gmpqc_supported_keymgmt[] = {
    { GMPQC_HYBRID_KEM_NAME, "provider=gmpqc", gmpqc_keymgmt_functions },
    { NULL, NULL, NULL }
};
