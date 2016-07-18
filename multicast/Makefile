all: mc-server mc-client

mc-server: mc-server.c mc.h
	gcc -Wall -g mc-server.c -o mc-server


mc-client: mc-client.c mc.h
	gcc -Wall -g mc-client.c -o mc-client

clean:
	rm -f mc-client mc-server a.out



