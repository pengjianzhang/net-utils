#!/bin/sh

echo "usage: curl.sh PORT"

curl --cacert chain.crt  --cert case2/case2.crt  --key case2/case2.key  https://hostcase1:$1
