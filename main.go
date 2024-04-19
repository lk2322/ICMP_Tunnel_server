package main

import (
	"encoding/binary"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func disablePingReply() {
	err := os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1"), 0644)
	if err != nil {
		log.Fatalf("Failed to disable ping reply: %v", err)
	}
}

func enablePingReply() {
	err := os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("0"), 0644)
	if err != nil {
		log.Fatalf("Failed to enable ping reply: %v", err)
	}
}

// HandleTCP handle TCP package and send res back
func HandleTCP(addr net.Addr, data []byte) ([]byte, error) {
	log.Println(data)
	port_binary := data[2:4]
	portInt := binary.BigEndian.Uint16(port_binary)
	addr = &net.TCPAddr{
		IP:   addr.(*net.IPAddr).IP,
		Port: int(portInt),
	}
	log.Printf("Connecting to %v", "127.0.0.1:8082")
	conn, err := net.Dial("tcp", "government.ru:80")
	if err != nil {
		log.Println("Failed to connect to %v: %v", addr, err)
		return nil, err

	}
	defer conn.Close()
	_, err = conn.Write(data)
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	log.Printf(string(buf))
	if err != nil {
		log.Println("Failed to write to connection: %v", err)
		return nil, err
	}
	return buf[:n], nil

}

func WriteBytes(conn *icmp.PacketConn, bytes []byte, addr net.Addr) {
	if _, err := conn.WriteTo(bytes, addr); err != nil {
		log.Fatalf("Failed to write to connection: %v", err)
	}

}

func handleICMPPackets(conn *icmp.PacketConn) {
	for {
		buf := make([]byte, 65535)
		n, addr, err := conn.ReadFrom(buf)
		log.Println(addr)
		if err != nil {
			log.Fatalf("Failed to read from connection: %v", err)
		}
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
		if err != nil {
			log.Println("Failed to parse ICMP message: %v", err)
		}
		log.Printf("Get ICMP packet Type: %v Code: %v \n", int(msg.Type.(ipv4.ICMPType)), msg.Code)
		var bytes []byte
		switch msg.Code {
		case 255:
			// Handle "our" packet
			msg.Type = ipv4.ICMPTypeEchoReply
			go func() {
				data, err := HandleTCP(addr, msg.Body.(*icmp.Echo).Data)
				if err != nil {
					return
				}
				msg.Body = &icmp.Echo{
					ID:   msg.Body.(*icmp.Echo).ID,
					Seq:  msg.Body.(*icmp.Echo).Seq,
					Data: data,
				}
				bytes, _ = msg.Marshal(nil)
				WriteBytes(conn, bytes, addr)
				log.Printf("Sent ICMP packet Type: %v Code: %v \n", int(msg.Type.(ipv4.ICMPType)), msg.Code)

			}()
		default:
			msg.Type = ipv4.ICMPTypeEchoReply
			bytes, _ = msg.Marshal(nil)
			WriteBytes(conn, bytes, addr)
			log.Printf("Sent ICMP packet Type: %v Code: %v \n", int(msg.Type.(ipv4.ICMPType)), msg.Code)

		}

	}
}

func main() {
	disablePingReply()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range c {
			enablePingReply()
			os.Exit(0)
		}
	}()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Failed to listen for ICMP packets: %v", err)
	}
	defer conn.Close()

	handleICMPPackets(conn)
}
