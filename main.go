package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smux "github.com/xtaci/smux"
)

const (
	// Optimized buffer sizes
	tcpBufferSize = 64 * 1024  // 64KB for TCP
	udpBufferSize = 4 * 1024   // 4KB for UDP (handles most packets + some batching)
)

// Connection management configuration
var (
	// TCP settings
	tcpKeepalive       = 60 * time.Second  // TCP keepalive interval
	tcpKeepAlivePeriod = 30 * time.Second  // TCP keepalive probe interval
	tcpIdleTimeout     = 5 * time.Minute   // Close idle TCP connections after 5 minutes
	
	// UDP settings
	udpSessionTimeout  = 2 * time.Minute   // Close idle UDP sessions after 2 minutes
	udpCleanupInterval = 30 * time.Second  // How often to check for stale UDP sessions
	
	// Session monitoring
	sessionPingInterval = 10 * time.Second // How often to check session health
)

// Global tunnel state tracking
var tunnelActive int32 // atomic: 0 = no tunnel, 1 = tunnel active

// Buffer pools for zero-copy optimizations
var (
	tcpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, tcpBufferSize)
		},
	}
	
	udpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, udpBufferSize)
		},
	}
)

// Connection tracking
type ConnectionTracker struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionInfo
	counter     int64
}

type ConnectionInfo struct {
	id        string
	conn      net.Conn
	createdAt time.Time
	lastSeen  time.Time
	connType  string // "tcp" or "udp"
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*ConnectionInfo),
	}
}

func (ct *ConnectionTracker) Add(conn net.Conn, connType string) string {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	id := fmt.Sprintf("%s_%d", connType, atomic.AddInt64(&ct.counter, 1))
	now := time.Now()
	
	ct.connections[id] = &ConnectionInfo{
		id:        id,
		conn:      conn,
		createdAt: now,
		lastSeen:  now,
		connType:  connType,
	}
	
	return id
}

func (ct *ConnectionTracker) Update(id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	if info, exists := ct.connections[id]; exists {
		info.lastSeen = time.Now()
	}
}

func (ct *ConnectionTracker) Remove(id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	delete(ct.connections, id)
}

func (ct *ConnectionTracker) CleanupStale() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	now := time.Now()
	cleaned := 0
	
	for id, info := range ct.connections {
		var timeout time.Duration
		if info.connType == "tcp" {
			timeout = tcpIdleTimeout
		} else {
			timeout = udpSessionTimeout
		}
		
		if now.Sub(info.lastSeen) > timeout {
			log.Printf("Closing stale %s connection %s (idle for %v)", 
				info.connType, id, now.Sub(info.lastSeen))
			info.conn.Close()
			delete(ct.connections, id)
			cleaned++
		}
	}
	
	return cleaned
}

func (ct *ConnectionTracker) Stats() (int, int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	tcp, udp := 0, 0
	for _, info := range ct.connections {
		if info.connType == "tcp" {
			tcp++
		} else {
			udp++
		}
	}
	
	return tcp, udp
}

var globalConnTracker = NewConnectionTracker()

type UDPSession struct {
	stream     *smux.Stream
	clientAddr *net.UDPAddr
	lastSeen   time.Time
	mu         sync.RWMutex
}

func (us *UDPSession) UpdateActivity() {
	us.mu.Lock()
	us.lastSeen = time.Now()
	us.mu.Unlock()
}

func (us *UDPSession) IsStale() bool {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return time.Since(us.lastSeen) > udpSessionTimeout
}

type UDPForwarder struct {
	sessions sync.Map // string -> *UDPSession
	session  *smux.Session
}

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host (used in vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
	forward := flag.String("forward", "", "Local TCP ports to forward to, comma-separated (used in vpn mode)")
	forwardudp := flag.String("forwardudp", "", "Local UDP ports to forward to, comma-separated (used in vpn mode)")
	token := flag.String("token", "", "Pre-shared token required for tunnel auth (required)")
	nonat := flag.Bool("nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
	flag.Parse()

	if *token == "" {
		log.Fatal("You must provide -token on both sides")
	}

	// Start connection cleanup goroutine
	go func() {
		ticker := time.NewTicker(udpCleanupInterval)
		defer ticker.Stop()
		
		for range ticker.C {
			cleaned := globalConnTracker.CleanupStale()
			if cleaned > 0 {
				tcp, udp := globalConnTracker.Stats()
				log.Printf("Cleaned up %d stale connections. Active: %d TCP, %d UDP", cleaned, tcp, udp)
			}
		}
	}()

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("Relay mode requires -port")
		}
		runRelay(*port, *token)
	case "vpn":
		if *host == "" || *port == "" || (*forward == "" && *forwardudp == "") {
			log.Fatal("VPN mode requires -host, -port, and at least one of -forward or -forwardudp")
		}
		runVPN(*host, *port, *forward, *forwardudp, *token, *nonat)
	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}

// Configure TCP connection with keepalive and timeouts
func configureTCPConnection(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil // Not a TCP connection
	}
	
	// Enable TCP keepalive
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable keepalive: %v", err)
	}
	
	// Set keepalive period
	if err := tcpConn.SetKeepAlivePeriod(tcpKeepalive); err != nil {
		return fmt.Errorf("failed to set keepalive period: %v", err)
	}
	
	return nil
}

func parsePorts(portList string) ([]string, error) {
	if portList == "" {
		return nil, nil
	}
	
	ports := strings.Split(portList, ",")
	var validPorts []string
	
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", port)
		}
		
		validPorts = append(validPorts, port)
	}
	
	return validPorts, nil
}

func runRelay(listenPort, expectedToken string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Relay: failed to listen on %s: %v", listenPort, err)
	}
	log.Printf("Relay: listening for tunnel on :%s", listenPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Relay: accept error: %v", err)
			continue
		}

		// Configure the tunnel connection
		if err := configureTCPConnection(conn); err != nil {
			log.Printf("Relay: failed to configure connection: %v", err)
			conn.Close()
			continue
		}

		// Check if a tunnel is already active
		if atomic.LoadInt32(&tunnelActive) == 1 {
			log.Printf("Relay: rejecting connection from %s - tunnel already active", conn.RemoteAddr())
			conn.Close()
			continue
		}

		log.Printf("Relay: incoming tunnel from %s", conn.RemoteAddr())
		go handleTunnel(conn, expectedToken)
	}
}

func handleTunnel(rawConn net.Conn, expectedToken string) {
	defer rawConn.Close()
	
	// Ensure we clear the tunnel state when this function exits
	defer func() {
		atomic.StoreInt32(&tunnelActive, 0)
		log.Printf("Relay: tunnel closed, cleared active state")
	}()

	session, err := smux.Server(rawConn, smux.DefaultConfig())
	if err != nil {
		log.Printf("Failed to create smux server: %v", err)
		return
	}
	defer session.Close()

	// Accept control stream for handshake
	controlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("Failed to accept control stream: %v", err)
		return
	}

	reader := bufio.NewReader(controlStream)

	// Read token
	tokenLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		log.Printf("Failed to read token: %v", err)
		return
	}
	receivedToken := strings.TrimSpace(tokenLine)

	// Read forward ports
	forwardLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		log.Printf("Failed to read forward ports: %v", err)
		return
	}
	forwardPortsStr := strings.TrimSpace(forwardLine)

	// Read forward UDP ports
	forwardUDPLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		log.Printf("Failed to read forward UDP ports: %v", err)
		return
	}
	forwardUDPPortsStr := strings.TrimSpace(forwardUDPLine)

	controlStream.Close()

	// Validate token
	if !constantTimeEqual(receivedToken, expectedToken) {
		log.Printf("Relay: invalid token from %s", rawConn.RemoteAddr())
		return
	}

	// Parse ports
	forwardPorts, err := parsePorts(forwardPortsStr)
	if err != nil {
		log.Printf("Invalid TCP forward ports: %v", err)
		return
	}

	forwardUDPPorts, err := parsePorts(forwardUDPPortsStr)
	if err != nil {
		log.Printf("Invalid UDP forward ports: %v", err)
		return
	}

	if len(forwardPorts) == 0 && len(forwardUDPPorts) == 0 {
		log.Printf("No forward ports specified")
		return
	}

	// Mark tunnel as active after successful authentication
	atomic.StoreInt32(&tunnelActive, 1)
	log.Printf("Relay: authenticated tunnel - TCP:%v UDP:%v", forwardPorts, forwardUDPPorts)

	// Create context for managing tunnel lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Cancel context when tunnel closes

	// Start TCP listeners
	var listeners []net.Listener
	var udpListeners []*net.UDPConn
	defer func() {
		log.Printf("Relay: cleaning up %d TCP listeners and %d UDP listeners", len(listeners), len(udpListeners))
		for _, listener := range listeners {
			listener.Close()
		}
		for _, udpListener := range udpListeners {
			udpListener.Close()
		}
	}()

	for _, port := range forwardPorts {
		listener, err := net.Listen("tcp", ":"+port)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", port, err)
			return
		}
		listeners = append(listeners, listener)
		log.Printf("Relay: listening on :%s for TCP clients", port)

		go func(l net.Listener, p string) {
			defer l.Close()
			for {
				// Check if tunnel is still active
				select {
				case <-ctx.Done():
					log.Printf("Relay: TCP listener on port %s shutting down", p)
					return
				default:
				}

				clientConn, err := l.Accept()
				if err != nil {
					// Check if it's because we're shutting down
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("Relay: TCP accept error on port %s: %v", p, err)
						return
					}
				}

				// Configure client connection
				if err := configureTCPConnection(clientConn); err != nil {
					log.Printf("Failed to configure client connection: %v", err)
					clientConn.Close()
					continue
				}

				go handleClientWithContext(ctx, clientConn, p, session)
			}
		}(listener, port)
	}

	// Start UDP listeners
	for _, port := range forwardUDPPorts {
		udpAddr, err := net.ResolveUDPAddr("udp", ":"+port)
		if err != nil {
			log.Printf("Failed to resolve UDP address :%s: %v", port, err)
			return
		}
		udpListener, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Printf("Failed to listen on UDP port %s: %v", port, err)
			return
		}
		udpListeners = append(udpListeners, udpListener)
		log.Printf("Relay: listening on :%s for UDP clients", port)

		udpForwarder := &UDPForwarder{session: session}
		go handleUDPRelayWithContext(ctx, udpListener, udpForwarder, port)
		
		// Start UDP session cleanup for this forwarder
		go cleanupUDPSessionsWithContext(ctx, udpForwarder)
	}

	// Wait for session to close naturally - this will detect broken connections
	// without false positives from aggressive monitoring
	go func() {
		for !session.IsClosed() {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("Relay: session accept failed (%v), cancelling tunnel", err)
				cancel()
				break
			}
			
			// Handle any unexpected streams
			if stream != nil {
				go func(s *smux.Stream) {
					// Try to read the protocol line to determine stream type
					reader := bufio.NewReader(s)
					protoLine, err := reader.ReadString('\n')
					if err != nil {
						s.Close()
						return
					}
					protoLine = strings.TrimSpace(protoLine)
					
					parts := strings.SplitN(protoLine, ":", 2)
					if len(parts) != 2 {
						s.Close()
						return
					}
					
					protocol := parts[0]
					targetPort := parts[1]
					
					// This should not happen in relay mode, but handle it gracefully
					log.Printf("Relay: unexpected stream %s:%s", protocol, targetPort)
					s.Close()
				}(stream)
			}
		}
	}()

	// Wait for context to be cancelled (session closed or error)
	<-ctx.Done()
	log.Printf("Relay: tunnel context cancelled, cleaning up")
}

func cleanupUDPSessionsWithContext(ctx context.Context, forwarder *UDPForwarder) {
	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var toDelete []string
			
			forwarder.sessions.Range(func(key, value interface{}) bool {
				sessionKey := key.(string)
				session := value.(*UDPSession)
				
				if session.IsStale() {
					toDelete = append(toDelete, sessionKey)
					session.stream.Close()
				}
				
				return true
			})
			
			for _, key := range toDelete {
				forwarder.sessions.Delete(key)
			}
			
			if len(toDelete) > 0 {
				log.Printf("Cleaned up %d stale UDP sessions", len(toDelete))
			}
		}
	}
}

func handleClientWithContext(ctx context.Context, clientConn net.Conn, port string, session *smux.Session) {
	defer clientConn.Close()

	// Check if tunnel is still active
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Track this connection
	connID := globalConnTracker.Add(clientConn, "tcp")
	defer globalConnTracker.Remove(connID)

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	// Send protocol message
	protocolMsg := fmt.Sprintf("TCP:%s\n", port)
	_, err = stream.Write([]byte(protocolMsg))
	if err != nil {
		log.Printf("Failed to write protocol message: %v", err)
		return
	}

	// Proxy the connection with optimized copying and activity tracking
	proxyPairOptimizedWithTrackingAndContext(ctx, clientConn, stream, connID)
}

func handleClient(clientConn net.Conn, port string, session *smux.Session) {
	// This is kept for backward compatibility, but creates a background context
	ctx := context.Background()
	handleClientWithContext(ctx, clientConn, port, session)
}

func handleUDPRelayWithContext(ctx context.Context, udpListener *net.UDPConn, forwarder *UDPForwarder, targetPort string) {
	defer udpListener.Close()
	
	// Use pooled buffer for UDP operations
	buffer := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buffer)

	for {
		// Check if tunnel is still active
		select {
		case <-ctx.Done():
			log.Printf("Relay: UDP listener on port %s shutting down", targetPort)
			return
		default:
		}

		// Set a read timeout so we can check context periodically
		udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))
		
		n, clientAddr, err := udpListener.ReadFromUDP(buffer)
		if err != nil {
			// Check if it's a timeout and context is still active
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue loop to check context
			}
			
			// Check if we're shutting down
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("UDP read error on port %s: %v", targetPort, err)
				return
			}
		}

		sessionKey := fmt.Sprintf("%s:%s", clientAddr.String(), targetPort)

		if sessionVal, exists := forwarder.sessions.Load(sessionKey); exists {
			session := sessionVal.(*UDPSession)
			session.UpdateActivity()
			_, err = session.stream.Write(buffer[:n])
			if err != nil {
				session.stream.Close()
				forwarder.sessions.Delete(sessionKey)
			}
			continue
		}

		// Create new UDP session
		stream, err := forwarder.session.OpenStream()
		if err != nil {
			continue
		}

		protocolMsg := fmt.Sprintf("UDP:%s\n", targetPort)
		_, err = stream.Write([]byte(protocolMsg))
		if err != nil {
			stream.Close()
			continue
		}

		session := &UDPSession{
			stream:     stream,
			clientAddr: clientAddr,
			lastSeen:   time.Now(),
		}

		forwarder.sessions.Store(sessionKey, session)

		// Start response handler with pooled buffer
		go func(s *UDPSession, key string) {
			defer s.stream.Close()
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)

			for {
				// Check context
				select {
				case <-ctx.Done():
					forwarder.sessions.Delete(key)
					return
				default:
				}

				n, err := s.stream.Read(buffer)
				if err != nil {
					break
				}

				_, err = udpListener.WriteToUDP(buffer[:n], s.clientAddr)
				if err != nil {
					break
				}
				
				s.UpdateActivity()
			}

			forwarder.sessions.Delete(key)
		}(session, sessionKey)

		// Forward initial packet
		session.UpdateActivity()
		_, err = session.stream.Write(buffer[:n])
		if err != nil {
			session.stream.Close()
		}
	}
}

func handleUDPRelay(udpListener *net.UDPConn, forwarder *UDPForwarder, targetPort string) {
	// This is kept for backward compatibility, but creates a background context
	ctx := context.Background()
	handleUDPRelayWithContext(ctx, udpListener, forwarder, targetPort)
}

func cleanupUDPSessions(forwarder *UDPForwarder) {
	// This is kept for backward compatibility, but creates a background context
	ctx := context.Background()
	cleanupUDPSessionsWithContext(ctx, forwarder)
}

// Get the public IP address of this machine
func getPublicIP() (net.IP, error) {
	// First try to get IP by connecting to a well-known address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// Get the public IP and create appropriate dialers
func setupDialers() (net.IP, *net.Dialer, *net.Dialer, error) {
	publicIP, err := getPublicIP()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get public IP: %v", err)
	}

	log.Printf("VPN: using source IP %s for local connections", publicIP)

	// Create TCP dialer with public IP as source
	tcpDialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: publicIP},
		Timeout:   30 * time.Second,
	}

	// Create UDP dialer with public IP as source  
	udpDialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{IP: publicIP},
		Timeout:   30 * time.Second,
	}

	return publicIP, tcpDialer, udpDialer, nil
}

func runVPN(relayHost, relayPort, forwardPorts, forwardUDPPorts, token string, nonat bool) {
	relayAddr := net.JoinHostPort(relayHost, relayPort)

	tcpPorts, err := parsePorts(forwardPorts)
	if err != nil {
		log.Fatalf("VPN: invalid TCP forward ports: %v", err)
	}

	udpPorts, err := parsePorts(forwardUDPPorts)
	if err != nil {
		log.Fatalf("VPN: invalid UDP forward ports: %v", err)
	}

	var tcpDialer, udpDialer *net.Dialer

	// Setup dialers with public IP only if -nonat is specified
	if nonat {
		_, tcpDialer, udpDialer, err = setupDialers()
		if err != nil {
			log.Fatalf("VPN: failed to setup dialers: %v", err)
		}
	}

	handshakeMsg := fmt.Sprintf("%s\n%s\n%s\n", token, forwardPorts, forwardUDPPorts)

	for {
		log.Printf("VPN: dialing relay %s", relayAddr)
		relayConn, err := net.Dial("tcp", relayAddr)
		if err != nil {
			log.Printf("VPN: failed to connect: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Configure relay connection
		if err := configureTCPConnection(relayConn); err != nil {
			log.Printf("VPN: failed to configure relay connection: %v", err)
			relayConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		session, err := smux.Client(relayConn, smux.DefaultConfig())
		if err != nil {
			relayConn.Close()
			log.Printf("VPN: failed to create smux client: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Send handshake
		ctrl, err := session.OpenStream()
		if err != nil {
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to open control stream: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		_, err = ctrl.Write([]byte(handshakeMsg))
		if err != nil {
			ctrl.Close()
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to send handshake: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		ctrl.Close()

		log.Printf("VPN: session established - TCP:%v UDP:%v", tcpPorts, udpPorts)

		// Handle incoming streams
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("VPN: session accept error: %v", err)
				break
			}
			go handleVPNStream(stream, tcpPorts, udpPorts, tcpDialer, udpDialer)
		}

		session.Close()
		relayConn.Close()
		log.Printf("VPN: session closed, will reconnect in 5 seconds")
		time.Sleep(5 * time.Second)
	}
}

func handleVPNStream(stream *smux.Stream, tcpPorts, udpPorts []string, tcpDialer, udpDialer *net.Dialer) {
	defer stream.Close()

	reader := bufio.NewReader(stream)
	protoLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("VPN: failed to read protocol line: %v", err)
		return
	}
	protoLine = strings.TrimSpace(protoLine)

	parts := strings.SplitN(protoLine, ":", 2)
	if len(parts) != 2 {
		log.Printf("VPN: invalid protocol line: %s", protoLine)
		return
	}

	protocol := parts[0]
	targetPort := parts[1]

	if protocol == "TCP" && contains(tcpPorts, targetPort) {
		var localConn net.Conn
		var err error
		
		// Use custom dialer if provided (nonat mode), otherwise use default
		if tcpDialer != nil {
			localConn, err = tcpDialer.Dial("tcp", "127.0.0.1:"+targetPort)
		} else {
			localConn, err = net.Dial("tcp", "127.0.0.1:"+targetPort)
		}
		
		if err != nil {
			log.Printf("VPN: failed to connect to local TCP port %s: %v", targetPort, err)
			return
		}
		defer localConn.Close()

		// Configure local connection
		if err := configureTCPConnection(localConn); err != nil {
			log.Printf("VPN: failed to configure local connection: %v", err)
			return
		}

		// Track this connection
		connID := globalConnTracker.Add(localConn, "tcp")
		defer globalConnTracker.Remove(connID)

		proxyPairOptimizedWithTrackingAndContext(context.Background(), localConn, stream, connID)

	} else if protocol == "UDP" && contains(udpPorts, targetPort) {
		udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
		if err != nil {
			log.Printf("VPN: failed to resolve UDP address for port %s: %v", targetPort, err)
			return
		}

		var udpConn net.Conn
		
		// Use custom dialer if provided (nonat mode), otherwise use default
		if udpDialer != nil {
			udpConn, err = udpDialer.Dial("udp", udpAddr.String())
		} else {
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
		}
		
		if err != nil {
			log.Printf("VPN: failed to connect to local UDP port %s: %v", targetPort, err)
			return
		}
		defer udpConn.Close()

		// Track this connection
		connID := globalConnTracker.Add(udpConn, "udp")
		defer globalConnTracker.Remove(connID)

		// Bidirectional UDP forwarding with pooled buffers and activity tracking
		done := make(chan struct{}, 2)

		// Stream to UDP
		go func() {
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)
			
			for {
				// Set read deadline
				stream.SetReadDeadline(time.Now().Add(udpSessionTimeout))
				
				n, err := stream.Read(buffer)
				if err != nil {
					break
				}
				
				globalConnTracker.Update(connID)
				_, err = udpConn.Write(buffer[:n])
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		// UDP to Stream
		go func() {
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)
			
			for {
				// Set read deadline
				udpConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
				
				n, err := udpConn.Read(buffer)
				if err != nil {
					break
				}
				
				globalConnTracker.Update(connID)
				_, err = stream.Write(buffer[:n])
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		<-done

	} else {
		log.Printf("VPN: unauthorized protocol/port: %s", protoLine)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Optimized proxy function with connection tracking, timeouts and context awareness
func proxyPairOptimizedWithTrackingAndContext(ctx context.Context, a net.Conn, b net.Conn, connID string) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			// Set read deadline to detect idle connections
			a.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			
			n, err := a.Read(buffer)
			if err != nil {
				break
			}
			
			// Update connection activity
			globalConnTracker.Update(connID)
			
			// Set write deadline
			b.SetWriteDeadline(time.Now().Add(30 * time.Second))
			
			_, err = b.Write(buffer[:n])
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			// Set read deadline to detect idle connections
			b.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			
			n, err := b.Read(buffer)
			if err != nil {
				break
			}
			
			// Update connection activity
			globalConnTracker.Update(connID)
			
			// Set write deadline
			a.SetWriteDeadline(time.Now().Add(30 * time.Second))
			
			_, err = a.Write(buffer[:n])
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Optimized proxy function with connection tracking and timeouts (backward compatibility)
func proxyPairOptimizedWithTracking(a net.Conn, b net.Conn, connID string) {
	ctx := context.Background()
	proxyPairOptimizedWithTrackingAndContext(ctx, a, b, connID)
}

// Optimized proxy function using pooled buffers and io.CopyBuffer (original)
func proxyPairOptimized(a net.Conn, b net.Conn) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)
		io.CopyBuffer(b, a, buffer)
		done <- struct{}{}
	}()

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)
		io.CopyBuffer(a, b, buffer)
		done <- struct{}{}
	}()

	<-done
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
