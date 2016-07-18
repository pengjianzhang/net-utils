#!/bin/sh


CACERT=CA/cacert.pem

CERT=client-key/client.crt
KEY=client-key/client.key

curl --cacert $CACERT --cert $CERT --key $KEY	 https://test:9988

