INCLUDE=/root/async/openssl/include

LIBDEPS=-L/root/async/openssl/lib -lcrypto -ldl -pthread  
CFLAGS=-DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_THREADS -DOPENSSL_NO_STATIC_ENGINE -DOPENSSL_PIC -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DRC4_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DPADLOCK_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/root/async/openssl/ssl\"" -DENGINESDIR="\"/root/async/net-utils/rkey\"" -Wall -O0 -g -pthread -m64 -DL_ENDIAN  -Wa,--noexecstack -fPIC -DOPENSSL_USE_NODELETE

rkey.so: e_rkey.c
	gcc  -I$(INCLUDE) $(CFLAGS)	-c e_rkey.c -o e_rkey.o
	LD_LIBRARY_PATH=.: gcc $(CFLAGS)	-Wl,-znodelete -m64 -shared -Wl,-Bsymbolic -Wl,-soname=rkey.so -o rkey.so e_rkey.o $(LIBDEPS)

clean:
	rm -f *.o *.so
