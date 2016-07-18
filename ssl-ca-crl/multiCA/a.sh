name=sha2

OPENSSL=/usr/bin/openssl-apps
OPENSSL=openssl

rm -f $name.key $name.csr $name.crt

$OPENSSL genrsa -out $name.key 1024



#$OPENSSL req -out $name.csr   -key $name.key -new -sha256

#-subj "/C=cn/ST=anhui/O=banggoo/OU=$name/CN=banggoo.cn/emailAddress=banggoo@banggoo.cn"

$OPENSSL req -out $name.csr   -key $name.key -new -sha256 -subj "/C=cn/ST=anhui/O=banggoo/OU=$name/CN=banggoo.cn/emailAddress=banggoo@banggoo.cn"



KEY=rootCA/rootCA.key
CRT=rootCA/rootCA.crt  

echo ==
#$OPENSSL ca -keyfile r.key -cert r.crt -in $name.csr -out $name.crt -sha256 -config openssl.cnf
#$OPENSSL ca -keyfile r.key -cert r.crt -in $name.csr -out $name.crt 
#$OPENSSL ca -keyfile $KEY -cert $CRT -in $name.csr -out $name.crt  -sha256 -config openssl.cnf

$OPENSSL ca -keyfile $KEY -cert $CRT -in $name.csr -out $name.crt   -config openssl.cnf




echo ==

#-config ../rootca/openssl.cnf


