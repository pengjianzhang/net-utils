
SRC=latency.c

latency: $(SRC)
	gcc -O3 -g $(SRC) -o latency -lpthread -lssl -lcrypto

clean:
	rm -f latency
