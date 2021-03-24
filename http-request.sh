REQ='GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nUser-Agent: socat\r\nConnection: keep-alive\r\n\r'

SLEEP=4
SRV=127.0.0.1:80

function send_request()
{
        NUM=$1

        for ((i=1; i<=$NUM; i++))
        do
                echo -e $REQ
                sleep $SLEEP
        done

}

send_request 10 | socat - TCP4:$SRV
