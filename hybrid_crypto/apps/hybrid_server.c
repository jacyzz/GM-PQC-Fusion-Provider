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
    if (!defprov) { fprintf(stderr, "[server] failed to load default provider\n"); return 1; }
    int port = 5555;
    if (argc > 1) port = atoi(argv[1]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(port);
    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 1);
    printf("[server] listening on %d\n", port);
    int c = accept(s, NULL, NULL);
    printf("[server] client connected\n");

    // generate server keypair
    uint8_t *srv_pub = NULL, *srv_priv = NULL; size_t srv_pub_len = 0, srv_priv_len = 0;
    if (hybrid_kex_keygen(&srv_pub, &srv_pub_len, &srv_priv, &srv_priv_len) != 0) { fprintf(stderr, "keygen failed\n"); return 1; }

    // receive client pub
    uint32_t nlen = 0; if (recv_all(c, (uint8_t*)&nlen, sizeof(nlen)) != 0) return 1; size_t clen = ntohl(nlen);
    uint8_t *client_pub = (uint8_t*)malloc(clen); if (!client_pub) return 1; if (recv_all(c, client_pub, clen) != 0) return 1;

    // derive
    uint8_t *shared = NULL; size_t shared_len = 0; uint8_t *resp = NULL; size_t resp_len = 0;
    int drc = hybrid_kex_server_derive(&shared, &shared_len, &resp, &resp_len, client_pub, clen, srv_priv, srv_priv_len);
    if (drc != 0) { fprintf(stderr, "derive failed (code=%d, client_pub_len=%zu)\n", drc, clen); return 1; }

    // send response
    uint32_t rlen = htonl((uint32_t)resp_len);
    if (send_all(c, (uint8_t*)&rlen, sizeof(rlen)) != 0) return 1;
    if (send_all(c, resp, resp_len) != 0) return 1;
    printf("[server] shared_secret[0..3]=%02x%02x%02x%02x\n", shared[0], shared[1], shared[2], shared[3]);

    // SM4-GCM decrypt a message from client and reply
    uint8_t key[16]; memcpy(key, shared, 16);
    uint8_t iv[12]; // read IV from client
    uint32_t ct_len_n=0; uint32_t tag_len_n=0;
    if (recv_all(c, iv, sizeof(iv)) != 0) return 1;
    if (recv_all(c, (uint8_t*)&ct_len_n, sizeof(ct_len_n)) != 0) return 1; size_t ct_len = ntohl(ct_len_n);
    uint8_t *cipher = (uint8_t*)malloc(ct_len); if (!cipher) return 1;
    if (recv_all(c, cipher, ct_len) != 0) return 1;
    if (recv_all(c, (uint8_t*)&tag_len_n, sizeof(tag_len_n)) != 0) return 1; size_t tag_len = ntohl(tag_len_n);
    uint8_t *tag = (uint8_t*)malloc(tag_len); if (!tag) return 1;
    if (recv_all(c, tag, tag_len) != 0) return 1;

    EVP_CIPHER *sm4gcm = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (!sm4gcm) { fprintf(stderr, "[server] SM4-GCM not available via provider\n"); return 1; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, sm4gcm, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    int outl=0, tot=0; uint8_t *plain = (uint8_t*)malloc(ct_len);
    EVP_DecryptUpdate(ctx, plain, &outl, cipher, (int)ct_len); tot = outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, tag);
    int ok = EVP_DecryptFinal_ex(ctx, plain + tot, &outl);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(sm4gcm);
    if (ok != 1) { fprintf(stderr, "[server] GCM decrypt failed\n"); return 1; }
    tot += outl;
    printf("[server] received: %.*s\n", tot, (char*)plain);

    // reply with encrypted message
    const char *reply = "pong";
    uint8_t siv[12]; RAND_bytes(siv, sizeof(siv));
    sm4gcm = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
    if (!sm4gcm) { fprintf(stderr, "[server] SM4-GCM not available via provider\n"); return 1; }
    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, sm4gcm, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(siv), NULL);
    EVP_EncryptInit_ex(ectx, NULL, NULL, key, siv);
    int elen=0, etot=0; uint8_t enc[64];
    EVP_EncryptUpdate(ectx, enc, &elen, (const uint8_t*)reply, (int)strlen(reply)); etot = elen;
    EVP_EncryptFinal_ex(ectx, enc + etot, &elen); etot += elen;
    uint8_t tbuf[16]; int tlen = 16; EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, tlen, tbuf);
    EVP_CIPHER_CTX_free(ectx);
    EVP_CIPHER_free(sm4gcm);

    uint32_t elen_n = htonl((uint32_t)etot); uint32_t tlen_n = htonl((uint32_t)tlen);
    if (send_all(c, siv, sizeof(siv)) != 0) return 1;
    if (send_all(c, (uint8_t*)&elen_n, sizeof(elen_n)) != 0) return 1;
    if (send_all(c, enc, etot) != 0) return 1;
    if (send_all(c, (uint8_t*)&tlen_n, sizeof(tlen_n)) != 0) return 1;
    if (send_all(c, tbuf, tlen) != 0) return 1;

    free(resp); free(client_pub); free(srv_pub); free(srv_priv); free(shared);
    close(c); close(s);
    OQS_destroy();
    return 0;
}


