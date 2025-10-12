CC = gcc
CFLAGS = -O2 -Wall -Wextra -I/usr/local/include -I./common
LDFLAGS = -L/usr/local/lib64 -lssl -lcrypto -Wl,-rpath,/usr/local/lib64

# Enable GmSSL static usage when GMSSL=1 (optional)
ifeq ($(GMSSL),1)
  CFLAGS += -I/opt/gmssl/include
  LDFLAGS += -L/opt/gmssl/lib -lgmssl -ldl -lpthread
endif

.PHONY: all clean

all: kem_demo client server

common_objs = common/crypto_ctx.o common/metrics.o common/net.o

kem_demo: kem_demo.o $(common_objs)
	$(CC) $^ -o $@ $(LDFLAGS)

client: client.o $(common_objs)
	$(CC) $^ -o $@ $(LDFLAGS)

server: server.o $(common_objs)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f kem_demo client server *.o common/*.o


