package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"net/http"
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

func Csum(data []byte, srcip, dstip [4]byte) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	//fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		//fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}

// HandleIP обрабатывает IP-пакет, отправляет его на удаленный узел и возвращает ответ
func HandleHTTP(data []byte) ([]byte, error) {
	// Проверка минимального размера IP-заголовка
	if len(data) < 20 {
		return nil, fmt.Errorf("invalid IP packet")
	}
	// Извлечение IP-адреса назначения из IP-заголовка
	srcIP := net.IPv4(95, 217, 146, 251)
	dstIP := net.IPv4(data[16], data[17], data[18], data[19])

	// Извлечение протокола из IP-заголовка
	protocol := data[9]
	if protocol != 6 {
		return nil, fmt.Errorf("only TCP protocol is supported")
	}

	// Извлечение порта назначения из TCP-заголовка
	tcpHeaderOffset := 20
	dstPort := binary.BigEndian.Uint16(data[tcpHeaderOffset+2 : tcpHeaderOffset+4])
	srcPort := binary.BigEndian.Uint16(data[tcpHeaderOffset : tcpHeaderOffset+2])

	// Создание TCP-адреса
	addr := &net.IPAddr{
		IP: dstIP,
	}

	// Установка TCP-соединения
	conn, err := net.DialIP("ip4:tcp", nil, addr)
	if err != nil {
		log.Printf("Failed to connect to %v: %v", addr, err)
		return nil, err
	}
	defer conn.Close()
	tcp := data[20:]
	checksum := Csum(tcp, [4]byte(srcIP.To4()), [4]byte(dstIP.To4()))
	binary.BigEndian.PutUint16(tcp[16:18], checksum)
	_, err = conn.Write(tcp)
	if err != nil {
		log.Printf("Failed to write to connection: %v", err)
		return nil, err
	}

	// Чтение ответа
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return nil, err
	}
	binary.BigEndian.PutUint16(buf[0:2], dstPort)
	binary.BigEndian.PutUint16(buf[2:4], srcPort)
	buf[16] = 0
	buf[17] = 0
	checksum = Csum(buf[:n], [4]byte(dstIP.To4()), [4]byte(srcIP.To4()))
	binary.BigEndian.PutUint16(buf[16:18], checksum)
	log.Printf("Response from %v: %v", addr, buf[:n])
	return buf[:n], nil
}

func WriteBytes(conn *icmp.PacketConn, bytes []byte, addr net.Addr) {
	if _, err := conn.WriteTo(bytes, addr); err != nil {
		log.Println("Failed to write to connection: %v", err)
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
		switch msg.Code {
		case 255:
			// Handle "our" packet
			msg.Type = ipv4.ICMPTypeEchoReply
			go func() {
				r := &bytes.Buffer{}
				_, err = r.Write(msg.Body.(*icmp.Echo).Data)
				if err != nil {
					log.Println(err)
					return
				}
				req, err := http.ReadRequest(bufio.NewReader(r))

				if err != nil {
					log.Println(1, err)
					return
				}
				log.Println(req)
				resp, err := http.DefaultTransport.RoundTrip(req)
				if err != nil {
					log.Println(2, err)
					return
				}
				data := &bytes.Buffer{}
				err = resp.Write(data)
				if err != nil {
					log.Println(3, err)
					return
				}

				if err != nil {
					return
				}
				msg.Body = &icmp.Echo{
					ID:   msg.Body.(*icmp.Echo).ID,
					Seq:  msg.Body.(*icmp.Echo).Seq,
					Data: data.Bytes(),
				}
				byts, _ := msg.Marshal(nil)
				WriteBytes(conn, byts, addr)
				log.Printf("Sent ICMP packet Type: %v Code: %v \n", int(msg.Type.(ipv4.ICMPType)), msg.Code)

			}()
		default:
			msg.Type = ipv4.ICMPTypeEchoReply
			byts, _ := msg.Marshal(nil)
			WriteBytes(conn, byts, addr)
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
