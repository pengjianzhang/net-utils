all: client server wss

client: ssl-client.c
	gcc ssl-client.c -o client -lssl -lcrypto

wss: wss.c
	gcc wss.c -g -O0 -o wss -lssl -lcrypto

server: ssl-server.c
	gcc ssl-server.c -o server -lssl -lcrypto

clean:
	rm -f wss client server *.o



