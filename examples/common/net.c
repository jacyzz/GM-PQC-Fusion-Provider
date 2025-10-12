#include "net.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int parse_hostport(const char *hp, char *host, size_t hostsz, int *port) {
  const char *colon = strrchr(hp, ':');
  if (!colon) return 0;
  size_t hlen = (size_t)(colon - hp);
  if (hlen >= hostsz) return 0;
  memcpy(host, hp, hlen); host[hlen] = '\0';
  *port = atoi(colon + 1);
  return *port > 0 && *port < 65536;
}

int tcp_listen(const char *hostport) {
  char host[256]; int port;
  if (!parse_hostport(hostport, host, sizeof(host), &port)) return -1;
  int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
  int on = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = strcmp(host, "0.0.0.0") == 0 ? INADDR_ANY : inet_addr(host);
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
  if (listen(fd, 128) < 0) { close(fd); return -1; }
  return fd;
}

int tcp_accept(int listen_fd) {
  return accept(listen_fd, NULL, NULL);
}

int tcp_connect(const char *hostport) {
  char host[256]; int port;
  if (!parse_hostport(hostport, host, sizeof(host), &port)) return -1;
  int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
  struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = inet_addr(host);
  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
  return fd;
}

static int readn(int fd, void *buf, size_t len) {
  unsigned char *p = buf; size_t n = 0; while (n < len) {
    ssize_t r = read(fd, p + n, len - n); if (r <= 0) return -1; n += (size_t)r; }
  return 0;
}

static int writen(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf; size_t n = 0; while (n < len) {
    ssize_t r = write(fd, p + n, len - n); if (r <= 0) return -1; n += (size_t)r; }
  return 0;
}

int send_frame(int fd, unsigned char type, const unsigned char *buf, size_t len) {
  unsigned char hdr[5];
  uint32_t be = htonl((uint32_t)len);
  memcpy(hdr, &be, 4); hdr[4] = type;
  if (writen(fd, hdr, 5) < 0) return -1;
  if (len > 0 && writen(fd, buf, len) < 0) return -1;
  return 0;
}

int recv_frame(int fd, unsigned char *type, unsigned char **buf, size_t *len) {
  unsigned char hdr[5];
  if (readn(fd, hdr, 5) < 0) return -1;
  uint32_t be; memcpy(&be, hdr, 4); *type = hdr[4];
  *len = ntohl(be);
  *buf = NULL; if (*len) { *buf = malloc(*len); if (!*buf) return -1; if (readn(fd, *buf, *len) < 0) { free(*buf); return -1; }}
  return 0;
}

void close_fd(int fd) { if (fd >= 0) close(fd); }


