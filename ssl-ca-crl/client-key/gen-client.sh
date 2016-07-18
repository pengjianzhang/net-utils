#!/bin/sh

(umask 077; openssl genrsa 1024 > client.key)

openssl req  -new -key client.key -out client.csr




