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
  const char *connect = argval(argc, argv, "--connect", "127.0.0.1:8443");
  const char *aead = argval(argc, argv, "--aead", "aes-128-gcm");
  size_t payload = (size_t)strtoul(argval(argc, argv, "--payload", "1024"), NULL, 10);
  size_t n = (size_t)strtoul(argval(argc, argv, "--n", "1000"), NULL, 10);

  CryptoCtx c; if (!crypto_init(&c, provider)) { fprintf(stderr, "provider load fail\n"); return 1; }
  int fd = tcp_connect(connect); if (fd < 0) { fprintf(stderr, "connect fail\n"); crypto_cleanup(&c); return 2; }

  unsigned char type; unsigned char *buf=NULL; size_t blen=0;
  if (recv_frame(fd, &type, &buf, &blen) < 0 || type != T_SERVER_HELLO) { fprintf(stderr, "bad server hello\n"); close_fd(fd); crypto_cleanup(&c); return 3; }
  /* parse kem name + pubkey */
  size_t kemlen = strnlen((char*)buf, blen);
  if (kemlen >= blen) { fprintf(stderr, "hello parse fail\n"); free(buf); close_fd(fd); crypto_cleanup(&c); return 4; }
  const char *kem = (const char*)buf;
  unsigned char *pub = buf + kemlen + 1; size_t publen = blen - kemlen - 1;

  if (strcmp(mode, "pqc") != 0) { fprintf(stderr, "SM mode not yet implemented in client minimal demo. Use --mode pqc.\n"); free(buf); close_fd(fd); crypto_cleanup(&c); return 90; }

  unsigned char *ct=NULL,*ss=NULL; size_t ctlen=0,sslen=0;
  if (!kem_encap(kem, pub, publen, &ct, &ctlen, &ss, &sslen)) { fprintf(stderr, "encap fail\n"); free(buf); close_fd(fd); crypto_cleanup(&c); return 5; }
  free(buf);
  send_frame(fd, T_CLIENT_KEM, ct, ctlen); OPENSSL_free(ct);

  /* Derive traffic key with SHA3-HKDF as default on client */
  unsigned char key[16], iv[12];
  unsigned char info[] = {0x01};
  if (!hkdf_sha3(ss, sslen, info, sizeof(info), key, sizeof(key)) || !hkdf_sha3(ss, sslen, info, sizeof(info), iv, sizeof(iv))) {
    fprintf(stderr, "hkdf fail\n"); OPENSSL_free(ss); close_fd(fd); crypto_cleanup(&c); return 6;
  }
  OPENSSL_free(ss);

  /* Init AEAD and send n encrypted data frames */
  AeadCtx aead_ctx; if (!aead_init(&aead_ctx, aead, key, sizeof(key), iv, sizeof(iv))) {
    fprintf(stderr, "aead init fail\n"); close_fd(fd); crypto_cleanup(&c); return 7;
  }
  Metrics m; metrics_start(&m);
  unsigned char *payload_buf = malloc(payload); if (!payload_buf) { fprintf(stderr, "oom\n"); aead_cleanup(&aead_ctx); close_fd(fd); crypto_cleanup(&c); return 8; }
  memset(payload_buf, 'A', payload);
  size_t ct_buf_cap = payload + 32; /* room for tag */
  unsigned char *ct_buf = malloc(ct_buf_cap);
  if (!ct_buf) { fprintf(stderr, "oom\n"); free(payload_buf); aead_cleanup(&aead_ctx); close_fd(fd); crypto_cleanup(&c); return 9; }
  for (size_t i=0;i<n;i++) {
    size_t ct_len = 0;
    if (!aead_seal(&aead_ctx, payload_buf, payload, ct_buf, &ct_len)) { fprintf(stderr, "encrypt fail\n"); break; }
    if (send_frame(fd, T_DATA, ct_buf, ct_len) < 0) { fprintf(stderr, "send fail\n"); break; }
    metrics_add(&m, payload, 1);
  }
  metrics_end(&m); metrics_print(&m);
  free(ct_buf);
  free(payload_buf);
  aead_cleanup(&aead_ctx);

  close_fd(fd); crypto_cleanup(&c); return 0;
}


