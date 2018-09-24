

 ./configure    --prefix=/opt/nginx  --with-cc-opt="-g -O0 -I/root/quic/openssl/include"\
                --with-cc-opt="-I$OPENSSL_LIB/include" \
                --with-ld-opt="-Wl,-rpath=$OPENSSL_LIB/lib -L$OPENSSL_LIB/lib -lssl -lcrypto" \
                --add-module=$NGX_QUIC


