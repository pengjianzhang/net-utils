
openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout test.key -out test.crt -subj "/C=cn/ST=bj/O=test/OU=dev/CN=test.cn/emailAddress=admin@test.cn"

openssl x509 -noout -text -in test.crt



