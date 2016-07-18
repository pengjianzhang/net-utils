#!/bin/sh

openvpn --mktun --dev tun77
ip link set tun77 up
ip addr add 10.0.0.1/24 dev tun77
ping 10.0.0.2
