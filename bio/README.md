# bio example

## Build

yum install libevent-devel
make

## Run

### input from file
./client 127.0.0.1 443 < get.txt

### input from keyboard

'''
./client 127.0.0.1 443
> GET / HTTP/1.1
> Host: 127.0.0.
>
'''

## Exit

ctl + C
