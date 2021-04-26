package main

import (
    "log"
    "net"
    "flag"
)

var ip string
var port string

func flagInit() {
    flag.StringVar(&ip, "ip", "0.0.0.0", "ip")
    flag.StringVar(&port, "port", "1234", "port")
    flag.Parse()
}

func serve(pc net.PacketConn, addr net.Addr) {
    client := addr.String()
    str := "Client " + client + "\n"
    b := []byte(str)
    pc.WriteTo(b, addr)
}

func main() {
   flagInit()

    pc, err := net.ListenPacket("udp", ip + ":" + port)
    if err != nil {
        log.Fatal(err)
    }
    defer pc.Close()
    buf := make([]byte, 2000)
    for {
        _, addr, err := pc.ReadFrom(buf)
        if err != nil {
            continue
        }
        go serve(pc, addr)
    }
}

