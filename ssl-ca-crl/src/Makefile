all: client server

client: ssl-client.c
	gcc -g ssl-client.c -o client -lssl

server: ssl-server.c
	gcc -g ssl-server.c -o server -lssl

clean:
	rm -f client server *.o 



