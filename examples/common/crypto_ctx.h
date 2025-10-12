#pragma once
#include <openssl/evp.h>

typedef struct {
  OSSL_PROVIDER *prov_default;
  OSSL_PROVIDER *prov_extra; /* oqsprovider or your provider */
  EVP_PKEY *kem_key;         /* server-side KEM key (PQC) */
} CryptoCtx;

/* provider management */
int crypto_init(CryptoCtx *c, const char *provider_name);
void crypto_cleanup(CryptoCtx *c);

/* KEM */
int kem_generate(CryptoCtx *c, const char *kem_name);
int kem_export_public(CryptoCtx *c, unsigned char **pub, size_t *publen);
int kem_encap(const char *kem_name, const unsigned char *pub, size_t publen,
              unsigned char **ct, size_t *ctlen,
              unsigned char **ss, size_t *sslen);
int kem_decap(CryptoCtx *c, const unsigned char *ct, size_t ctlen,
              unsigned char **ss, size_t *sslen);

/* HKDF (SHA3 与 SM3 两版) */
int hkdf_sha3(const unsigned char *ikm, size_t ikm_len,
              const unsigned char *info, size_t info_len,
              unsigned char *out, size_t out_len);
int hkdf_sm3(const unsigned char *ikm, size_t ikm_len,
             const unsigned char *info, size_t info_len,
             unsigned char *out, size_t out_len);

/* AEAD (GCM family) */
typedef struct {
  EVP_CIPHER *cipher;          /* fetched cipher */
  EVP_CIPHER_CTX *enc;         /* encrypt ctx */
  EVP_CIPHER_CTX *dec;         /* decrypt ctx */
  unsigned char key[32];       /* up to AES-256 */
  size_t key_len;
  unsigned char iv[12];        /* base IV */
  uint64_t seq;                /* per-record counter */
  size_t tag_len;              /* default 16 */
} AeadCtx;

int aead_init(AeadCtx *a, const char *aead_name,
              const unsigned char *key, size_t key_len,
              const unsigned char *iv, size_t iv_len);
void aead_cleanup(AeadCtx *a);
/* Encrypt: produce ciphertext||tag. out must have at least in_len + tag_len bytes. */
int aead_seal(AeadCtx *a, const unsigned char *in, size_t in_len,
              unsigned char *out, size_t *out_len);
/* Decrypt: input is ciphertext||tag. */
int aead_open(AeadCtx *a, const unsigned char *in, size_t in_len,
              unsigned char *out, size_t *out_len);


