
OPENSSL=/root/openssl-1.1.1/build

OPENSSL_INCLUDE=$(OPENSSL)/include
OPENSSL_LIB=$(OPENSSL)/lib


CFLAGS=-g -O3 -I$(OPENSSL_INCLUDE)
LDFLAGS=-Wall -Wl,-rpath=$(OPENSSL_LIB) -L$(OPENSSL_LIB) -lssl -lcrypto


async: async.c
	gcc $(CFLAGS) async.c -o async $(LDFLAGS)

clean:
	rm async 
