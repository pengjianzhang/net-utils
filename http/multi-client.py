#!/usr/bin/env python
 
import httplib
import sys
import time
import threading

 
 
def session(httpClient, url):    

    body = ""
    headers = {
        "Connection":"Keep-Alive",
        "Accept": "text/plain",
        "Accept-Encoding":"gzip, deflate" }

    httpClient.request('GET', url,body,headers)
    response = httpClient.getresponse()

#    print response.status
#    print response.msg
    data = response.read()

#    print len(data)
#    print "="

#    httpClient.close()

def request(req,repeat,srv):
    httpClient = None
    i = 0
    j = 0
    try:
       for i in range(req):
            httpClient = httplib.HTTPConnection(srv, 80,timeout=30)
            for j in range(repeat):
                #print "/"
                session(httpClient,"/")
                #print "/watch.php"
                session(httpClient,"/watch.php")
                #time.sleep(8)
                print j
            httpClient.close()
            print i
            #time.sleep(10)

    except Exception, e:
        print "error"
        print e
#    finally:
#        if httpClient:
#            httpClient.close()




class Client(threading.Thread):
    def __init__ (self,req_num,repeat, ip):
        threading.Thread.__init__(self)
        self.ip = ip
        self.req_num = req_num
        self.repeat = repeat
        self.setDaemon(True)
    def run(self):
        request(self.req_num, self.repeat,self.ip)
   
def multi_thread(t_n,req_num,repeat,ip):
    threads = []
    for i in range(t_n):
        new_t = Client(req_num,repeat,ip) 
        threads.append(new_t)

    for i in threads:
        i.start()

    while True:
        time.sleep(10)



if len(sys.argv) != 5:
    print "Usage: ", sys.argv[0], "thread-num request-num repeat-num vs-ip\n"
else:
    multi_thread(int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]), sys.argv[4])

