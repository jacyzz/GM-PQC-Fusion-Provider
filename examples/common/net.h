#pragma once
#include <stddef.h>

int tcp_listen(const char *hostport);
int tcp_accept(int listen_fd);
int tcp_connect(const char *hostport);

int send_frame(int fd, unsigned char type, const unsigned char *buf, size_t len);
int recv_frame(int fd, unsigned char *type, unsigned char **buf, size_t *len);

void close_fd(int fd);


