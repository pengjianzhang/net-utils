all: http-server tcp-client

CFLGAS=-O3 -g
LDFLAGS=-levent

http-server: http-server.c
	gcc ${CFLGAS} -o $@ $^ $(LDFLAGS)

tcp-client: tcp-client.c
	gcc ${CFLGAS} -o $@ $^ $(LDFLAGS)

clean:
	rm -f http-server tcp-client
