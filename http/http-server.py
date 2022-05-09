#!/usr/bin/python

import os, sys
import posixpath
import BaseHTTPServer
import time
import shutil
import random



from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler


class myHTTPHandle(BaseHTTPRequestHandler):


    def set_keepalive(self):
        self.protocol_version = "HTTP/1.1"
        self.send_header("Connection", "Keep-Alive")

    def copyfile(self,src,dst):
        shutil.copyfileobj(src, dst)


    def c100(self):
        self.protocol_version = "HTTP/1.0"
        self.send_response(100)
        self.end_headers()
        self.wfile.write("")

    def chunked(self):
        self.protocol_version = "HTTP/1.1"
        s0 = "6\r\n22222\n\r\n" * 100
        s1 = "6;  asdjlf\r\n11111\n\r\n" * 100
        s2 = "6\r\n22223\n\r\n"
        zero = "0\r\n"
        trailer = "hello: thisistrailer\r\n" * 10
        buf = s0 + s1 + s2 + zero + trailer + "\r\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Transfer-Encoding", "chunked")
        self.set_keepalive()
        self.end_headers()
        self.wfile.write(buf)

    def freelen(self):
        self.protocol_version = "HTTP/1.1"
        s0 = 'aaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbb\n' * 200
        s1 = "end\n"
        buf = s0 + s1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(buf)

    def content_length(self,code,buf):
        clen = len(buf)
        self.send_response(code)
        self.send_header('Content-type','text/html')
        self.send_header('Content-Length',str(clen))
        self.end_headers()
        if clen > 0:
            self.wfile.write(buf)

    def zero(self):
        self.protocol_version = "HTTP/1.1"
        self.content_length(200,"")

    def hello_word(self):
        self.protocol_version = "HTTP/1.1"
        self.content_length(200,"hello,world\n")

    def bye(self):
        self.close_connection = True
        self.content_length(200,"bye~~~~~~~\n")

    def send_err(self,code,msg):
        self.close_connection = True
        self.content_length(400,msg)

    def send_file(self):
        self.protocol_version = "HTTP/1.1"
        path = "./" + self.path
        f = None

        try:
            f = open(path, 'rb')
        except IOError:
            print path
            self.send_err(404, "File  not found: " + self.path + "\n")
            return

        f = open(path, 'rb')
        buf = f.read()
        fs = os.fstat(f.fileno())
        self.send_response(200)
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.send_header("Content-Type", "text/html")
        self.set_keepalive()
        self.end_headers()
        self.wfile.write(buf)
        f.close()

    def __location(self,buf,url):

        self.close_connection = True
        self.send_response(302)
#        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.send_header('Content-Length',str(len(buf)))
#        self.send_header('Location',"http://192.168.4.101:8000/a.txt")
        self.send_header('Location',url)
        self.end_headers()
        self.wfile.write(buf)

    def location(self,buf):
        id = random.randint(0,5)
        print id
        urls = [
        "http://10.80.5.163:9080/a.txt",
        "http://10.80.5.164:9080/a.txt",
        "http://10.80.5.164:9081/a.txt",
        "http://10.80.5.164:9082/a.txt",
        "http://10.80.5.168:9080/a.txt",
        "http://10.80.5.169:9081/a.txt",
        "http://10.80.5.169:9082/a.txt"]

        self.__location(buf,urls[id])


    def hello_word(self):
        self.protocol_version = "HTTP/1.1"
        self.content_length(200,"hello,world\n")


    def do_GET(self):

        if self.path == "/100":
            self.c100()
        elif self.path == "/location":
            print "hi-----"
            self.location("hello~~i~ii~iii~~~~~~~~~~\n")
        elif self.path == "/chunked" :
            self.chunked()

        elif self.path == "/0":
            self.zero()

        elif self.path == "/close":
            self.bye()

        elif self.path == "/favicon.ico":
            self.send_file()
        elif self.path == "/freelen":
            self.freelen()
        else :
            self.send_file()

def start_server(ip,port):
    http_server = HTTPServer((ip,port), myHTTPHandle)
    http_server.serve_forever()



if len(sys.argv) != 3:
    print "Usage: ", sys.argv[0], " ip port\n"
else:
    start_server(sys.argv[1],int(sys.argv[2]))


