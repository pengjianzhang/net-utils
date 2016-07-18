#!/bin/sh

echo "usage: server.sh SERVERPATH PORT"


$1 -ssl $2 case1/case1.crt case1/case1.key  chain

