package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	// Open a connection to the SQLite database.
	// The database file "mydatabase.db" will be created if it doesn't exist.
	db, err := sql.Open("sqlite", "mydatabase.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Failed to close database: %v", err)
		}
	}()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Successfully connected to SQLite database!")

	// You can now use 'db' to execute queries, prepare statements, etc.
	// For example:
	// _, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
	// if err != nil {
	// 	log.Fatalf("Failed to create table: %v", err)
	// }
	// log.Println("Table 'users' checked/created successfully.")

	targetHost := "google.com" // Or an IP like "8.8.8.8"
	timeout := 1 * time.Second

	log.Printf("Pinging %s (IPv4) with timeout %v...\n", targetHost, timeout)
	success, err := PingHost(targetHost, timeout)

	if err != nil {
		// This covers errors like resolution failure, listen failure, etc.
		log.Fatalf("Ping process failed: %v\n", err)
	}

	if success {
		log.Printf("Ping to %s successful!\n", targetHost)
	} else {
		// This indicates a timeout (no reply within the duration).
		log.Printf("Ping to %s timed out or no reply received.\n", targetHost)
	}

}

func PingHost(address string, timeout time.Duration) (bool, error) {
	// Resolve the address to an IPAddr. We're focusing on IPv4.
	// For IPv6, you would use "ip6" and corresponding ipv6.ICMPType* constants.
	ipAddr, err := net.ResolveIPAddr("ip4", address)
	if err != nil {
		return false, fmt.Errorf("failed to resolve address '%s': %w", address, err)
	}

	// Listen for ICMP packets on all available IPv4 interfaces.
	// The network string "ip4:icmp" specifies ICMP over IPv4.
	// The address "0.0.0.0" means listen on all local IPv4 addresses.
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf("failed to listen for ICMP packets: %w", err)
	}
	defer conn.Close()

	// Construct the ICMP message (Echo Request).
	// Using the process ID for the ICMP ID is a common practice to help
	// distinguish replies if multiple ping processes are running.
	// The sequence number can be a simple counter if sending multiple pings.
	packetId := os.Getpid() & 0xffff
	echoMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho, // ICMP Echo Request for IPv4
		Code: 0,                 // Code 0 for Echo Request
		Body: &icmp.Echo{
			ID:   packetId,       // Use process ID (masked to 16 bits)
			Seq:  1,              // Sequence number (can be incremented for multiple pings)
			Data: []byte("PING"), // Arbitrary payload
		},
	}

	msgBytes, err := echoMessage.Marshal(nil)
	if err != nil {
		return false, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	err = conn.IPv4PacketConn().SetTTL(3)
	if err != nil {
		return false, fmt.Errorf("failed to set TTL: %w", err)
	}

	// Send the ICMP message to the target IP address.
	startTime := time.Now()
	if _, err := conn.WriteTo(msgBytes, ipAddr); err != nil {
		return false, fmt.Errorf("failed to write ICMP message to %s: %w", ipAddr, err)
	}

	// Set a deadline for reading the reply.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Buffer to hold the ICMP reply.
	// 1500 bytes is a common MTU size and should be sufficient for an ICMP reply.
	replyBytes := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(replyBytes)
	pingTime := time.Now().Sub(startTime)
	if err != nil {
		// Check if the error is a timeout.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, nil // Timeout occurred, not a "failure" error.
		}
		return false, fmt.Errorf("failed to read ICMP reply from %s after %v: %w", ipAddr, pingTime, err)
	}

	// Parse the received ICMP message.
	// The protocol for ICMP over IPv4 is 1.
	// ipv4.ICMPTypeEchoReply.Protocol() correctly provides this.
	receivedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), replyBytes[:n])
	if err != nil {
		return false, fmt.Errorf("failed to parse ICMP reply from %s: %w", peer, err)
	}

	// Check if the received message is an Echo Reply.
	switch receivedMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		// Optionally, you could further validate if receivedMsg.Body.(*icmp.Echo).ID
		// and .Seq match the ones sent, for stricter validation.
		switch ie := receivedMsg.Body.(type) {
		case *icmp.Echo:
			if ie.ID != packetId {
				log.Printf("Got echo_reply not matching our Id.  ignoring. rm:[%+v] peer:[%+v] ie:[%+v]", receivedMsg, peer, ie)
			}
			log.Printf("happy reply. rm:[%+v] peer:[%+v] ie:[%+v]", receivedMsg, peer, ie)
		default:
			log.Printf("Unexpected ICMP response type: %+v", ie)
		}
		log.Printf("Received ICMP after %v reply from %s: %v", pingTime, peer, receivedMsg)
		return true, nil // Successfully received an echo reply.
	case ipv4.ICMPTypeTimeExceeded:
		switch ie := receivedMsg.Body.(type) {
		case *icmp.Echo:
			if ie.ID != packetId {
				log.Printf("Got echo_reply not matching our Id.  ignoring. rm:[%+v] peer:[%+v] ie:[%+v]", receivedMsg, peer, ie)
			}
			log.Printf("happy reply. rm:[%+v] peer:[%+v] ie:[%+v]", receivedMsg, peer, ie)
		default:
			log.Printf("Unexpected ICMP response type: %+v", ie)
		}
		return false, fmt.Errorf("time exceeded in %v from %s, message %+v", pingTime, peer, receivedMsg)
	default:
		// Received an ICMP message, but not the Echo Reply we expected.
		return false, fmt.Errorf("received unexpected ICMP message in %v type %v from %s, message %v", pingTime, receivedMsg.Type, peer, receivedMsg)
	}
}
