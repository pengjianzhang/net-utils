all: client server

client: ssl-client.c
	gcc ssl-client.c -o client -lssl -lcrypto


server: ssl-server.c
	gcc ssl-server.c -o server -lssl -lcrypto

clean:
	rm -f client server *.o 



