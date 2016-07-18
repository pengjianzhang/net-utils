#!/usr/bin/python

import os, sys
import posixpath
import BaseHTTPServer
import time
import shutil



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
        buf = '6\r\n11111\n\r\n6\r\n22222\n\r\n0\r\n\r\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Transfer-Encoding", "chunked")
        self.set_keepalive()
        self.end_headers()
        self.wfile.write(buf)

    def content_length(self,code,buf):
        clen = len(buf)
        self.send_response(code)
        self.send_header('Content-type','text/html')
        self.send_header('Content-Length',str(clen))
        self.end_headers()
        self.wfile.write(buf)

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

    def do_GET(self):

        if self.path == "/100":
            self.c100()
        elif self.path == "/chunked" :
            self.chunked()

        elif self.path == "/close":
            self.bye()    

        elif self.path == "/favicon.ico":
            self.send_file()
        else :
            self.send_file()

def start_server():
    http_server = HTTPServer(('0.0.0.0', 8000), myHTTPHandle)
    http_server.serve_forever()




start_server()


