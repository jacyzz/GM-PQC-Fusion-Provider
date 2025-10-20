#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <oqs/oqs.h>
#include "../include/hybrid_kex.h"

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0; ssize_t n;
    while (off < len) { n = send(fd, buf + off, len - off, 0); if (n <= 0) return -1; off += (size_t)n; }
    return 0;
}
static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0; ssize_t n;
    while (off < len) { n = recv(fd, buf + off, len - off, 0); if (n <= 0) return -1; off += (size_t)n; }
    return 0;
}

int main(int argc, char **argv) {
    OQS_init();
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) { fprintf(stderr, "[client] failed to load default provider\n"); return 1; }
    const char *host = "127.0.0.1"; int port = 5555;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(port); inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) { perror("connect"); return 1; }
    printf("[client] connected to %s:%d\n", host, port);

    // generate client keypair
    uint8_t *cli_pub = NULL, *cli_priv = NULL; size_t cli_pub_len = 0, cli_priv_len = 0;
    if (hybrid_kex_keygen(&cli_pub, &cli_pub_len, &cli_priv, &cli_priv_len) != 0) { fprintf(stderr, "keygen failed\n"); return 1; }

    // send public key
    uint32_t nlen = htonl((uint32_t)cli_pub_len);
    if (send_all(s, (uint8_t*)&nlen, sizeof(nlen)) != 0) return 1;
    if (send_all(s, cli_pub, cli_pub_len) != 0) return 1;

    // receive server response
    uint32_t rlen = 0; if (recv_all(s, (uint8_t*)&rlen, sizeof(rlen)) != 0) return 1; size_t resp_len = ntohl(rlen);
    uint8_t *resp = (uint8_t*)malloc(resp_len); if (!resp) return 1; if (recv_all(s, resp, resp_len) != 0) return 1;

    // derive
    uint8_t *shared = NULL; size_t shared_len = 0;
    int drc = hybrid_kex_client_derive(&shared, &shared_len, resp, resp_len, cli_priv, cli_priv_len);
    if (drc != 0) { fprintf(stderr, "client derive failed (code=%d, resp_len=%zu)\n", drc, resp_len); return 1; }
    printf("[client] shared_secret[0..3]=%02x%02x%02x%02x\n", shared[0], shared[1], shared[2], shared[3]);

    // send SM4-GCM encrypted ping and read reply
    uint8_t key[16]; memcpy(key, shared, 16);
    uint8_t iv[12]; RAND_bytes(iv, sizeof(iv));
    EVP_CIPHER *sm4gcm = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (!sm4gcm) { fprintf(stderr, "[client] SM4-GCM not available via provider\n"); return 1; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, sm4gcm, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    const char *msg = "ping"; int outl=0, tot=0; uint8_t enc[64];
    EVP_EncryptUpdate(ctx, enc, &outl, (const uint8_t*)msg, (int)strlen(msg)); tot = outl;
    EVP_EncryptFinal_ex(ctx, enc + tot, &outl); tot += outl;
    uint8_t tag[16]; int tlen = 16; EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tlen, tag);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(sm4gcm);

    uint32_t clen_n = htonl((uint32_t)tot), tlen_n = htonl((uint32_t)tlen);
    if (send_all(s, iv, sizeof(iv)) != 0) return 1;
    if (send_all(s, (uint8_t*)&clen_n, sizeof(clen_n)) != 0) return 1;
    if (send_all(s, enc, tot) != 0) return 1;
    if (send_all(s, (uint8_t*)&tlen_n, sizeof(tlen_n)) != 0) return 1;
    if (send_all(s, tag, tlen) != 0) return 1;

    // receive reply
    uint8_t siv[12]; uint32_t elen_n=0, tglen_n=0; if (recv_all(s, siv, sizeof(siv)) != 0) return 1;
    if (recv_all(s, (uint8_t*)&elen_n, sizeof(elen_n)) != 0) return 1; size_t elen = ntohl(elen_n);
    uint8_t *ec = (uint8_t*)malloc(elen); if (!ec) return 1; if (recv_all(s, ec, elen) != 0) return 1;
    if (recv_all(s, (uint8_t*)&tglen_n, sizeof(tglen_n)) != 0) return 1; size_t tglen = ntohl(tglen_n);
    uint8_t *tgbuf = (uint8_t*)malloc(tglen); if (!tgbuf) return 1; if (recv_all(s, tgbuf, tglen) != 0) return 1;

    sm4gcm = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (!sm4gcm) { fprintf(stderr, "[client] SM4-GCM not available via provider\n"); return 1; }
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, sm4gcm, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(siv), NULL);
    EVP_DecryptInit_ex(dctx, NULL, NULL, key, siv);
    int pl=0, pt=0; uint8_t *plain = (uint8_t*)malloc(elen);
    EVP_DecryptUpdate(dctx, plain, &pl, ec, (int)elen); pt = pl;
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, (int)tglen, tgbuf);
    int ok = EVP_DecryptFinal_ex(dctx, plain + pt, &pl);
    EVP_CIPHER_CTX_free(dctx);
    EVP_CIPHER_free(sm4gcm);
    if (ok != 1) { fprintf(stderr, "[client] GCM decrypt failed\n"); return 1; }
    pt += pl;
    printf("[client] received: %.*s\n", pt, (char*)plain);

    free(ec); free(tgbuf); free(plain);
    free(resp); free(cli_pub); free(cli_priv); free(shared);
    close(s);
    OQS_destroy();
    return 0;
}


