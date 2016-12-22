from websocket import create_connection
import time


while(1):

    ws = create_connection("ws://192.168.4.101:8080/")
    for i in range(0,100):
        i = i + 1
        print i
        msg = "Hello, World=============================++++++++++++++++++++++++++++++++++";
        ws.send(msg)
        print "Sent"
        print "Reeiving..."
        result =  ws.recv()
        print "Received '%s'" % result
    #    time.sleep(1)
    ws.close()
    #time.sleep(1)
