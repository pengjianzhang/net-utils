from socket import *
import sys
import time

IP='192.168.4.22'
PORT=80

BUFSIZE=40960

ADDR=(IP, PORT)

def http_request(ip,port,url):
    size = 0
    request = "GET " + url +  " HTTP/1.0\r\nUser-Agent: python\r\nHost: " + ip +"\r\nAccept: */*\r\n\r\n"


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
    while True:
        
        size = http_request(ip,port,url)
        bytes = bytes + size

        if(bytes >= speed):
            end = time.time()
            spend = end - start
            
            if(spend >= 1):
                print "speed is too high to handle"
            else:

                if bytes > 1024*1024:
                    bytes = bytes / (1024*1024)
                    print bytes,"MB/s"
                elif(bytes >= 1024):
                    bytes = bytes / 1024
                    print bytes,"KB/s"
                else:
                    print bytes,"B/s"

                time.sleep( 1 - spend)
                return



def http_speed(ip,port,url, speed, timeout):
    
    for i in range(0, timeout):
        print i
        http_speed_1(ip,port,url, speed)
    


def usage():
    print sys.argv[0], " ip port url speed timeout"


print len(sys.argv)

if len(sys.argv) != 6:
    usage()
else:
    ip      = sys.argv[1]
    port    = sys.argv[2]
    url     = sys.argv[3]
    speed   = sys.argv[4]
    timeout = sys.argv[5]
    
#    print ip,port,url,speed,timeout
    http_speed(ip,int(port),url, int(speed), int(timeout))







