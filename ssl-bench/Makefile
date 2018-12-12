OPENSSL=/root/openssl-1.1.1/build

ssl-bench: ssl-bench.c
#	gcc    -lssl -lcrypto -O3 ssl-bench.c -o ssl-bench
	gcc -I/root/openssl-1.1.1/build/include/ -Wl,-rpath,/root/openssl-1.1.1/build/lib -L/root/openssl-1.1.1/build/lib -lssl -lcrypto -lpthread -O3 ssl-bench.c -o ssl-bench
#	gcc  -I$(OPENSSL)/include $(OPENSSL)/lib/libcrypto.a $(OPENSSL)/lib/libssl.a ssl-bench.c -o ssl-bench
#	gcc  -I$(OPENSSL)/include $(OPENSSL)/lib/libcrypto.a $(OPENSSL)/lib/libssl.a ssl-bench.c -o ssl-bench

clean:
	rm -f ssl-bench *.o



