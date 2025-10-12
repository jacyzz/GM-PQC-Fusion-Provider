#include "common/crypto_ctx.h"
#include "common/net.h"
#include "common/metrics.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { T_SERVER_HELLO=1, T_CLIENT_KEM=2, T_DATA=3 };

static const char *argval(int argc, char **argv, const char *key, const char *def) {
  for (int i=1;i<argc-1;i++) if (strcmp(argv[i], key)==0) return argv[i+1];
  return def;
}

int main(int argc, char **argv) {
  const char *mode = argval(argc, argv, "--mode", "pqc");
  const char *provider = argval(argc, argv, "--provider", strcmp(mode,"pqc")==0?"oqsprovider":"default");
  const char *kem = argval(argc, argv, "--kem", "mlkem768");
  const char *aead = argval(argc, argv, "--aead", "aes-128-gcm");
  const char *listen = argval(argc, argv, "--listen", "0.0.0.0:8443");
  size_t payload = (size_t)strtoul(argval(argc, argv, "--payload", "1024"), NULL, 10);
  size_t n = (size_t)strtoul(argval(argc, argv, "--n", "1000"), NULL, 10);

  CryptoCtx c; if (!crypto_init(&c, provider)) { fprintf(stderr, "provider load fail\n"); return 1; }
  if (strcmp(mode, "pqc") == 0) {
    if (!kem_generate(&c, kem)) { fprintf(stderr, "kem keygen fail\n"); crypto_cleanup(&c); return 2; }
  } else {
    fprintf(stderr, "SM mode not yet implemented in server minimal demo. Use --mode pqc.\n"); crypto_cleanup(&c); return 90;
  }

  unsigned char *pub=NULL; size_t publen=0; if (!kem_export_public(&c, &pub, &publen)) { fprintf(stderr, "export pub fail\n"); crypto_cleanup(&c); return 3; }

  int lfd = tcp_listen(listen); if (lfd < 0) { fprintf(stderr, "listen fail\n"); OPENSSL_free(pub); crypto_cleanup(&c); return 4; }
  int fd = tcp_accept(lfd); if (fd < 0) { fprintf(stderr, "accept fail\n"); OPENSSL_free(pub); crypto_cleanup(&c); close_fd(lfd); return 5; }
  /* send ServerHello: kem name + pubkey */
  size_t hello_len = strlen(kem) + 1 + publen;
  unsigned char *hello = malloc(hello_len);
  memcpy(hello, kem, strlen(kem)+1); memcpy(hello + strlen(kem)+1, pub, publen);
  send_frame(fd, T_SERVER_HELLO, hello, hello_len);
  free(hello); OPENSSL_free(pub);

  unsigned char type; unsigned char *buf=NULL; size_t blen=0;
  if (recv_frame(fd, &type, &buf, &blen) < 0 || type != T_CLIENT_KEM) { fprintf(stderr, "bad client kem\n"); close_fd(fd); close_fd(lfd); crypto_cleanup(&c); return 6; }

  unsigned char *ss=NULL; size_t sslen=0; if (!kem_decap(&c, buf, blen, &ss, &sslen)) { fprintf(stderr, "decap fail\n"); free(buf); close_fd(fd); close_fd(lfd); crypto_cleanup(&c); return 7; }
  free(buf);

  /* Derive traffic key with SHA3-HKDF as default on server */
  unsigned char key[16], iv[12];
  unsigned char info[] = {0x01};
  if (!hkdf_sha3(ss, sslen, info, sizeof(info), key, sizeof(key)) || !hkdf_sha3(ss, sslen, info, sizeof(info), iv, sizeof(iv))) {
    fprintf(stderr, "hkdf fail\n"); OPENSSL_free(ss); close_fd(fd); close_fd(lfd); crypto_cleanup(&c); return 8;
  }
  OPENSSL_free(ss);

  /* Init AEAD and receive n encrypted data frames */
  AeadCtx aead_ctx; if (!aead_init(&aead_ctx, aead, key, sizeof(key), iv, sizeof(iv))) {
    fprintf(stderr, "aead init fail\n"); close_fd(fd); close_fd(lfd); crypto_cleanup(&c); return 9;
  }
  Metrics m; metrics_start(&m);
  for (size_t i=0;i<n;i++) {
    if (recv_frame(fd, &type, &buf, &blen) < 0 || type != T_DATA) { fprintf(stderr, "bad data frame\n"); break; }
    size_t pt_cap = blen; /* ciphertext includes tag; plaintext <= blen */
    unsigned char *pt = malloc(pt_cap);
    if (!pt) { fprintf(stderr, "oom\n"); free(buf); break; }
    size_t pt_len = 0;
    if (!aead_open(&aead_ctx, buf, blen, pt, &pt_len)) { fprintf(stderr, "decrypt fail\n"); free(pt); free(buf); break; }
    metrics_add(&m, pt_len, 1);
    free(pt);
    free(buf);
  }
  metrics_end(&m); metrics_print(&m);
  aead_cleanup(&aead_ctx);

  close_fd(fd); close_fd(lfd); crypto_cleanup(&c); return 0;
}


