all: client server

client: ssl-client.c
	gcc ssl-client.c -o client -lssl

server: ssl-server.c
	gcc ssl-server.c -o server -lssl

clean:
	rm -f client server *.o 



