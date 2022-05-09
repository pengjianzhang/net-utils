#!/usr/bin/env python

import httplib
import sys


def session(httpClient):

    url = raw_input("URL: ")
    conn = raw_input("Keep-Alive(y/n): ")
    body = ""
    if(conn == "y"):
        headers = {
            "Connection":"Keep-Alive",
            "Accept": "text/plain",
            "Accept-Encoding":"gzip, deflate" }
    else:
        headers = {
            "Accept": "text/plain"}

    httpClient.request('GET', url,body,headers)
    response = httpClient.getresponse()

    print response.status
    print response.msg
    data = response.read()


    print len(data)
    print ""

#    httpClient.close()


def request(srv):
    httpClient = None

    try:
        httpClient = httplib.HTTPConnection(srv, 80,timeout=30)
        while True:
            session(httpClient)

    except Exception, e:
        print "error"
        print e
#    finally:
#        if httpClient:
#            httpClient.close()




if len(sys.argv) != 2:
    print "Usage: ", sys.argv[0], " server\n"
else:
    request(sys.argv[1])
