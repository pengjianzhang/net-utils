#!/bin/sh


# -c chunk-num chunk-len
#  -l content-lenth
#   -b body-lenth

mkdir -p www


./gen_html -c 1 1 > www/c1
./gen_html -c 1 4 > www/c1_4
./gen_html -c 10000 1 > www/c1w_1
./gen_html -c 10000 4 > www/c1w_4
./gen_html -c 10000 1000 > www/c1w_1k
./gen_html -c 1000 100000 > www/c1k_10w
./gen_html -c 1000 100000 > www/c1k_10w

./gen_html -l 0  > www/l0
./gen_html -l 1  > www/l1
./gen_html -l 1000  > www/l1k
./gen_html -l 1000000  > www/l1m
./gen_html -l 10000000  > www/l10m

./gen_html -b 0  > www/b0
./gen_html -b 1  > www/b1
./gen_html -b 1000  > www/b1k
./gen_html -b 1000000  > www/b1m
./gen_html -b 10000000  > www/b10m




