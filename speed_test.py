from socket import *
import sys
import time

BUFSIZE=40960

RATE=1000

def http_request(ip,port,url):
    size = 0
    request = "GET " + url +  " HTTP/1.0\r\nUser-Agent: python\r\nHost: " + ip +"\r\nAccept: */*\r\n\r\n"


    ADDR=(ip,port)
    size = len(request)

    sk = socket(AF_INET, SOCK_STREAM)
    sk.connect(ADDR)
    sk.send(request)
    while True:    
        data=sk.recv(BUFSIZE)
        if not data:
            break
        size = size + len(data)
    sk.close()
    return size


def http_speed_1(ip,port,url, speed):
    
    start = time.time()
    spend = 0
    bytes = 0
    bits = 0
    while True:
        
        bytes = http_request(ip,port,url)
        bits = bytes * 8.0 + bits

        if(bits >= speed):
            end = time.time()
            spend = end - start
            
            if(spend >= 1):
                print "speed is too high to handle"
            else:
                if bits >= RATE*RATE:
                    bits = bits / (RATE*RATE)
                    print bits,"MBit/s"
                elif(bits >= RATE):
                    bits = bits / RATE
                    print bits,"KBit/s"
                else:
                    print bits,"Bit/s"

                time.sleep( 1 - spend)
                return

def http_speed(ip,port,url, speed, timeout):
    
    for i in range(0, timeout):
        http_speed_1(ip,port,url, speed)
    


def usage():
    print sys.argv[0], " ip port url speed(K/M) timeout"

if len(sys.argv) != 6:
    usage()
else:
    ip      = sys.argv[1]
    port    = sys.argv[2]
    url     = sys.argv[3]
    speed   = sys.argv[4]
    timeout = sys.argv[5]
    
    num,unit = int(speed[:-1]), speed[-1] #NUM K/M

    if((unit == 'K') or (unit == 'k')):
        num = num * RATE
    elif((unit == 'M') or (unit == 'm')):
        num = num * RATE * RATE
    else:
        num = 0
        usage()

    if num > 0:
        http_speed(ip,int(port),url, num, int(timeout))







