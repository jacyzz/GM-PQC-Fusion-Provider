#include "common/crypto_ctx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *argval(int argc, char **argv, const char *key, const char *def) {
  for (int i=1;i<argc-1;i++) if (strcmp(argv[i], key)==0) return argv[i+1];
  return def;
}

int main(int argc, char **argv) {
  const char *provider = argval(argc, argv, "--provider", "oqsprovider");
  const char *kem = argval(argc, argv, "--kem", "mlkem768");
  CryptoCtx c; if (!crypto_init(&c, provider)) { fprintf(stderr, "load providers failed\n"); return 1; }
  if (!kem_generate(&c, kem)) { fprintf(stderr, "kem keygen failed\n"); crypto_cleanup(&c); return 2; }
  unsigned char *pub=NULL; size_t publen=0; if (!kem_export_public(&c, &pub, &publen)) { fprintf(stderr, "export pub failed\n"); crypto_cleanup(&c); return 3; }
  unsigned char *ct=NULL,*ss1=NULL; size_t ctlen=0,sslen1=0;
  if (!kem_encap(kem, pub, publen, &ct, &ctlen, &ss1, &sslen1)) { fprintf(stderr, "encap failed\n"); OPENSSL_free(pub); crypto_cleanup(&c); return 4; }
  unsigned char *ss2=NULL; size_t sslen2=0; if (!kem_decap(&c, ct, ctlen, &ss2, &sslen2)) { fprintf(stderr, "decap failed\n"); OPENSSL_free(pub); OPENSSL_free(ct); OPENSSL_free(ss1); crypto_cleanup(&c); return 5; }
  int ok = (sslen1==sslen2) && (memcmp(ss1, ss2, sslen1)==0);
  printf("provider=%s kem=%s roundtrip=%s ct=%zu ss=%zu\n", provider, kem, ok?"OK":"FAIL", ctlen, sslen1);
  OPENSSL_free(pub); OPENSSL_free(ct); OPENSSL_free(ss1); OPENSSL_free(ss2); crypto_cleanup(&c);
  return ok?0:6;
}


