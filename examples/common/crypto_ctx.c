#include "crypto_ctx.h"
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

int crypto_init(CryptoCtx *c, const char *provider_name) {
  memset(c, 0, sizeof(*c));
  c->prov_default = OSSL_PROVIDER_load(NULL, "default");
  if (!c->prov_default) return 0;
  if (provider_name && strlen(provider_name) > 0 && strcmp(provider_name, "default") != 0) {
    c->prov_extra = OSSL_PROVIDER_load(NULL, provider_name);
    if (!c->prov_extra) return 0;
  }
  return 1;
}

void crypto_cleanup(CryptoCtx *c) {
  if (c->kem_key) EVP_PKEY_free(c->kem_key);
  if (c->prov_extra) OSSL_PROVIDER_unload(c->prov_extra);
  if (c->prov_default) OSSL_PROVIDER_unload(c->prov_default);
}

int kem_generate(CryptoCtx *c, const char *kem_name) {
  EVP_PKEY_CTX *genctx = EVP_PKEY_CTX_new_from_name(NULL, kem_name, NULL);
  if (!genctx) return 0;
  int ok = EVP_PKEY_keygen_init(genctx) > 0 && EVP_PKEY_generate(genctx, &c->kem_key) > 0;
  EVP_PKEY_CTX_free(genctx);
  return ok;
}

int kem_export_public(CryptoCtx *c, unsigned char **pub, size_t *publen) {
  if (!c->kem_key) return 0;
  *pub = NULL; *publen = 0;
  /* Export raw public key bytes via standard param name */
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(c->kem_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len) <= 0 || len == 0)
    return 0;
  unsigned char *out = OPENSSL_malloc(len);
  if (!out) return 0;
  if (EVP_PKEY_get_octet_string_param(c->kem_key, OSSL_PKEY_PARAM_PUB_KEY, out, len, &len) <= 0) {
    OPENSSL_free(out); return 0;
  }
  *pub = out; *publen = len; return 1;
}

int kem_encap(const char *kem_name, const unsigned char *pub, size_t publen,
              unsigned char **ct, size_t *ctlen,
              unsigned char **ss, size_t *sslen) {
  *ct = NULL; *ss = NULL; *ctlen = 0; *sslen = 0;
  /* Reconstruct peer public key from raw bytes */
  EVP_PKEY *peer = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, kem_name, NULL);
  if (!pctx) return 0;
  if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return 0; }
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub, publen);
  params[1] = OSSL_PARAM_construct_end();
  int ok = EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) > 0;
  EVP_PKEY_CTX_free(pctx);
  if (!ok || !peer) return 0;

  EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
  if (!ectx) { EVP_PKEY_free(peer); return 0; }
  ok = 0;
  if (EVP_PKEY_encapsulate_init(ectx, NULL) > 0) {
    size_t lct = 0, lss = 0;
    if (EVP_PKEY_encapsulate(ectx, NULL, &lct, NULL, &lss) > 0) {
      unsigned char *bct = OPENSSL_malloc(lct);
      unsigned char *bss = OPENSSL_malloc(lss);
      if (bct && bss && EVP_PKEY_encapsulate(ectx, bct, &lct, bss, &lss) > 0) {
        *ct = bct; *ctlen = lct; *ss = bss; *sslen = lss; ok = 1;
      } else {
        OPENSSL_free(bct);
        OPENSSL_free(bss);
      }
    }
  }
  EVP_PKEY_CTX_free(ectx);
  EVP_PKEY_free(peer);
  return ok;
}

int kem_decap(CryptoCtx *c, const unsigned char *ct, size_t ctlen,
              unsigned char **ss, size_t *sslen) {
  *ss = NULL; *sslen = 0;
  if (!c->kem_key) return 0;
  EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, c->kem_key, NULL);
  if (!dctx) return 0;
  int ok = 0;
  size_t lss = 0;
  if (EVP_PKEY_decapsulate_init(dctx, NULL) > 0 &&
      EVP_PKEY_decapsulate(dctx, NULL, &lss, ct, ctlen) > 0) {
    unsigned char *bss = OPENSSL_malloc(lss);
    if (bss && EVP_PKEY_decapsulate(dctx, bss, &lss, ct, ctlen) > 0) {
      *ss = bss; *sslen = lss; ok = 1;
    } else {
      OPENSSL_free(bss);
    }
  }
  EVP_PKEY_CTX_free(dctx);
  return ok;
}

static int hkdf_core(const char *digest_name,
                     const unsigned char *ikm, size_t ikm_len,
                     const unsigned char *info, size_t info_len,
                     unsigned char *out, size_t out_len) {
  int ok = 0;
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
  OSSL_PARAM params[5], *p = params;
  if (!kctx) goto end;
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)digest_name, 0);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0);
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, info_len);
  *p = OSSL_PARAM_construct_end();
  if (EVP_KDF_derive(kctx, out, out_len, params) > 0) ok = 1;
end:
  if (kctx) EVP_KDF_CTX_free(kctx);
  if (kdf) EVP_KDF_free(kdf);
  return ok;
}

int hkdf_sha3(const unsigned char *ikm, size_t ikm_len,
              const unsigned char *info, size_t info_len,
              unsigned char *out, size_t out_len) {
  return hkdf_core("SHA3-256", ikm, ikm_len, info, info_len, out, out_len);
}
int hkdf_sm3(const unsigned char *ikm, size_t ikm_len,
             const unsigned char *info, size_t info_len,
             unsigned char *out, size_t out_len) {
  return hkdf_core("SM3", ikm, ikm_len, info, info_len, out, out_len);
}

/* AEAD (GCM) */
static EVP_CIPHER *fetch_cipher(const char *name) {
  return EVP_CIPHER_fetch(NULL, name, NULL);
}

int aead_init(AeadCtx *a, const char *aead_name,
              const unsigned char *key, size_t key_len,
              const unsigned char *iv, size_t iv_len) {
  memset(a, 0, sizeof(*a));
  a->tag_len = 16;
  a->seq = 0;
  a->key_len = key_len;
  a->cipher = fetch_cipher(aead_name);
  if (!a->cipher) return 0;
  a->enc = EVP_CIPHER_CTX_new();
  a->dec = EVP_CIPHER_CTX_new();
  if (!a->enc || !a->dec) return 0;
  if (key_len > sizeof(a->key)) return 0;
  memcpy(a->key, key, key_len);
  if (iv_len != sizeof(a->iv)) return 0;
  memcpy(a->iv, iv, iv_len);
  return 1;
}

void aead_cleanup(AeadCtx *a) {
  if (a->enc) EVP_CIPHER_CTX_free(a->enc);
  if (a->dec) EVP_CIPHER_CTX_free(a->dec);
  if (a->cipher) EVP_CIPHER_free(a->cipher);
}

/* construct per-record IV = baseIV XOR seq (last 8 bytes) */
static void build_iv(const unsigned char base[12], uint64_t seq, unsigned char out[12]) {
  memcpy(out, base, 12);
  for (int i=0;i<8;i++) out[12-1-i] ^= (unsigned char)((seq >> (8*i)) & 0xff);
}

int aead_seal(AeadCtx *a, const unsigned char *in, size_t in_len,
              unsigned char *out, size_t *out_len) {
  unsigned char iv[12];
  build_iv(a->iv, a->seq++, iv);
  int len = 0, ctlen = 0;
  if (EVP_EncryptInit_ex(a->enc, a->cipher, NULL, NULL, NULL) <= 0) return 0;
  if (EVP_CIPHER_CTX_ctrl(a->enc, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(iv), NULL) <= 0) return 0;
  if (EVP_EncryptInit_ex(a->enc, NULL, NULL, a->key, iv) <= 0) return 0;
  if (EVP_EncryptUpdate(a->enc, out, &len, in, (int)in_len) <= 0) return 0;
  ctlen = len;
  if (EVP_EncryptFinal_ex(a->enc, out+ctlen, &len) <= 0) return 0;
  ctlen += len;
  if (EVP_CIPHER_CTX_ctrl(a->enc, EVP_CTRL_AEAD_GET_TAG, (int)a->tag_len, out+ctlen) <= 0) return 0;
  ctlen += (int)a->tag_len;
  *out_len = (size_t)ctlen;
  return 1;
}

int aead_open(AeadCtx *a, const unsigned char *in, size_t in_len,
              unsigned char *out, size_t *out_len) {
  if (in_len < a->tag_len) return 0;
  size_t mlen = in_len - a->tag_len;
  unsigned char iv[12];
  build_iv(a->iv, a->seq++, iv);
  int len = 0, ptlen = 0;
  if (EVP_DecryptInit_ex(a->dec, a->cipher, NULL, NULL, NULL) <= 0) return 0;
  if (EVP_CIPHER_CTX_ctrl(a->dec, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(iv), NULL) <= 0) return 0;
  if (EVP_DecryptInit_ex(a->dec, NULL, NULL, a->key, iv) <= 0) return 0;
  if (EVP_DecryptUpdate(a->dec, out, &len, in, (int)mlen) <= 0) return 0;
  ptlen = len;
  if (EVP_CIPHER_CTX_ctrl(a->dec, EVP_CTRL_AEAD_SET_TAG, (int)a->tag_len, (void*)(in+mlen)) <= 0) return 0;
  if (EVP_DecryptFinal_ex(a->dec, out+ptlen, &len) <= 0) return 0;
  ptlen += len;
  *out_len = (size_t)ptlen;
  return 1;
}


