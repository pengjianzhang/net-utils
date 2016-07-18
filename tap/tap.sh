#!/bin/sh

NAME=tap88
IP=192.168.4.71/24
MAC=00:1B:21:A6:2A:04 
openvpn --mktun --dev $NAME
ip link set $NAME  address $MAC 
ip link set $NAME up
ip addr add $IP dev $NAME 
#ping 10.0.0.2
#ip tuntap add gw200 mode tap

#ip link set gw200 up
