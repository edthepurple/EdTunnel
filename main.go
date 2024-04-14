package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

// Constants for keepalive
const (
	keepaliveInterval = 10 * time.Second
	keepaliveTimeout  = 30 * time.Second
	keepaliveMessage  = "keepalive"
)

// Session is the UDP session info
type Session struct {
	clientAddr *net.UDPAddr
	serverConn *net.UDPConn
	lastSeen   time.Time
}

// Forwarder is the info of forwarder
type Forwarder struct {
	fromAddr     *net.UDPAddr
	toAddr       *net.UDPAddr
	localConn    *net.UDPConn
	sessions     map[string]*Session
	allowedCIDRs []*net.IPNet // List of allowed CIDR blocks
	mu           sync.Mutex
}

// Define a key for XOR encryption
var xorKey = []byte("your_secret_key")

func main() {
	// Parse command line arguments
	fromAddrStr := flag.String("from", "0.0.0.0:27015", "UDP address to forward from")
	toAddrStr := flag.String("to", "127.0.0.1:8443", "UDP address to forward to")
	flag.Parse()

	fromAddr, err := net.ResolveUDPAddr("udp", *fromAddrStr)
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	toAddr, err := net.ResolveUDPAddr("udp", *toAddrStr)
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	// Read allowed CIDR blocks from allow.list file
	allowedCIDRs, err := readCIDRsFromFile("allow.list")
	if err != nil {
		log.Fatal("Error reading allowed CIDRs:", err)
	}

	// Create and start the UDP forwarder
	forwarder := NewForwarder(fromAddr, toAddr, allowedCIDRs)
	go forwarder.Start()

	// Wait for a termination signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	// Stop the forwarder on termination signal
	forwarder.Stop()
	log.Println("UDP forwarder stopped")
}

// NewForwarder creates a new UDP forwarder
func NewForwarder(fromAddr, toAddr *net.UDPAddr, allowedCIDRs []*net.IPNet) *Forwarder {
	// Attempt to listen on the local UDP address
	localConn, err := net.ListenUDP("udp", fromAddr)
	if err != nil {
		log.Fatal("Error listening on UDP address:", err)
	}

	// Attempt to establish a connection to the remote UDP address
	serverConn, err := net.DialUDP("udp", nil, toAddr)
	if err != nil {
		// Clean up local connection before exiting
		localConn.Close()
		log.Fatal("Error connecting to server:", err)
	}

	// Create the Forwarder instance
	forwarder := &Forwarder{
		fromAddr:     fromAddr,
		toAddr:       toAddr,
		localConn:    localConn,
		sessions:     make(map[string]*Session),
		allowedCIDRs: allowedCIDRs,
	}

	// Ensure cleanup in case of error during construction
	// Defer the closing of server connection
	defer func() {
		if err != nil {
			serverConn.Close()
		}
	}()

	return forwarder
}

// readCIDRsFromFile reads CIDR blocks from a file and returns a slice of *net.IPNet
func readCIDRsFromFile(filename string) ([]*net.IPNet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cidrs []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cidr := scanner.Text()
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, ipNet)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cidrs, nil
}

// Start starts the UDP forwarder
func (f *Forwarder) Start() {
	log.Printf("UDP forwarder started - From: %v, To: %v\n", f.fromAddr, f.toAddr)

	buffer := make([]byte, 1500)

	// Start keepalive loop
	go f.sendKeepalives()

	for {
		n, clientAddr, err := f.localConn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP:", err)
			continue
		}

		// Check if client's IP is allowed
		if !f.isAllowedClient(clientAddr.IP) {
			log.Printf("Connection from %s is not allowed\n", clientAddr.IP.String())
			continue
		}

		clientKey := fmt.Sprintf("%s:%d", clientAddr.IP.String(), clientAddr.Port)

		f.mu.Lock()
		session, ok := f.sessions[clientKey]
		if !ok {
			serverConn, err := net.DialUDP("udp", nil, f.toAddr)
			if err != nil {
				log.Println("Error connecting to server:", err)
				f.mu.Unlock()
				continue
			}

			session = &Session{
				clientAddr: clientAddr,
				serverConn: serverConn,
				lastSeen:   time.Now(),
			}

			f.sessions[clientKey] = session

			// Log new connection
			log.Printf("New session established with client: %s\n", clientKey)

			go f.handleSession(clientKey, session)
		} else {
			// Update last seen time for existing session
			session.lastSeen = time.Now()
		}
		f.mu.Unlock()

		// Encrypt the UDP packet before forwarding
		encryptPacket(buffer[:n])

		// Forward the UDP packet to the server
		_, err = session.serverConn.Write(buffer[:n])
		if err != nil {
			log.Println("Error forwarding UDP packet:", err)
		}
	}
}

// isAllowedClient checks if the client's IP is allowed based on the list of allowed CIDR blocks
func (f *Forwarder) isAllowedClient(clientIP net.IP) bool {
	for _, cidr := range f.allowedCIDRs {
		if cidr.Contains(clientIP) {
			return true
		}
	}
	return false
}

// handleSession handles a UDP session with XOR encryption
func (f *Forwarder) handleSession(clientKey string, session *Session) {
	buffer := make([]byte, 1500)

	for {
		n, _, err := session.serverConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Session %s closed\n", clientKey)

			f.mu.Lock()
			delete(f.sessions, clientKey)
			f.mu.Unlock()

			session.serverConn.Close()
			return
		}

		// Decrypt incoming packet
		decryptPacket(buffer[:n])

		// Forward the decrypted UDP packet back to the client
		_, err = f.localConn.WriteToUDP(buffer[:n], session.clientAddr)
		if err != nil {
			log.Println("Error forwarding UDP packet to client:", err)
		}
	}
}

// sendKeepalives periodically sends keepalive messages to all connected clients
func (f *Forwarder) sendKeepalives() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		<-ticker.C

		f.mu.Lock()
		for _, session := range f.sessions {
			_, err := session.serverConn.Write([]byte(keepaliveMessage))
			if err != nil {
				log.Printf("Error sending keepalive to %s: %v\n", session.clientAddr.String(), err)
			}
		}
		f.mu.Unlock()

		// Check for timed out clients
		f.checkTimeouts()
	}
}

// checkTimeouts checks for timed out clients and closes their sessions
func (f *Forwarder) checkTimeouts() {
	currentTime := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	for clientKey, session := range f.sessions {
		if currentTime.Sub(session.lastSeen) > keepaliveTimeout {
			log.Printf("Client %s timed out, closing session\n", clientKey)
			delete(f.sessions, clientKey)
			session.serverConn.Close()
		}
	}
}

// Stop stops the UDP forwarder
func (f *Forwarder) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, session := range f.sessions {
		session.serverConn.Close()
	}

	f.localConn.Close()
}

// Encrypt packet using XOR encryption
func encryptPacket(packet []byte) {
	for i := range packet {
		packet[i] ^= xorKey[i%len(xorKey)]
	}
}

// Decrypt packet using XOR encryption
func decryptPacket(packet []byte) {
	encryptPacket(packet) // XOR encryption is symmetric, so encryption and decryption are the same
}
