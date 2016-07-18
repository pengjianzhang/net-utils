openssl genrsa -out key_name.key 2048 
openssl req -out CSR.csr -key key_name.key -new -sha256

