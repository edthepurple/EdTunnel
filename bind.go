package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/smux"
)

const (
	TCP_FORWARD  = 1
	UDP_FORWARD  = 2
	SO_REUSEPORT = 15 // Linux SO_REUSEPORT
)

type ForwardRule struct {
	srcPort    string
	targetPort string
	proto      int
	bindAddr   string // Full bind address (ip:port)
}

type UDPSession struct {
	conn       *net.UDPConn
	stream     *smux.Stream
	clientAddr *net.UDPAddr
	lastActive time.Time
	closed     bool // guarded by mu; prevents double-close
	mu         sync.Mutex
}

type RelayConnection struct {
	host      string
	conn      net.Conn
	session   *smux.Session
	active    atomic.Bool
	connected atomic.Bool
	lastCheck time.Time
	mu        sync.Mutex
}

type RelayManager struct {
	relays        []*RelayConnection
	activeRelay   atomic.Value // *RelayConnection
	token         string
	forwardRules  string
	strategy      string // "multi" or "failover"
	reconnectChan chan string
	bindIP        string // IP to bind forwarded ports to
	mu            sync.RWMutex
}

// ActiveRelaySession tracks the current active session on the relay server
// to allow immediate cleanup when a VPN client reconnects
type ActiveRelaySession struct {
	session   *smux.Session
	listeners []io.Closer
	mu        sync.Mutex
}

var (
	mode       = flag.String("mode", "", "Mode: relay or vpn")
	port       = flag.String("port", "", "Relay server port (can be :8080 or 192.168.1.1:8080)")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")

	// Track current relay session for immediate cleanup on VPN reconnection
	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex
)

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	if *mode == "relay" {
		if *port == "" {
			log.Fatal("Port is required for relay mode")
		}
		runRelay()
	} else if *mode == "vpn" {
		if *host == "" {
			log.Fatal("Host is required for vpn mode")
		}
		runVPN()
	} else {
		log.Fatal("Invalid mode. Use 'relay' or 'vpn'")
	}
}

// parseBindAddress parses bind address and returns (bindIP, port)
// Supports formats: ":8080", "8080", "192.168.1.1:8080", "[::1]:8080"
func parseBindAddress(addr string) (bindIP string, bindPort string) {
	// If it starts with ":", it's just a port
	if strings.HasPrefix(addr, ":") {
		return "", addr[1:]
	}

	// Check if it contains a colon (might be ip:port or IPv6)
	if strings.Contains(addr, ":") {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// Might be just a port number
			return "", addr
		}
		return host, port
	}

	// Just a port number
	return "", addr
}

// makeBindAddress creates a bind address from IP and port
func makeBindAddress(bindIP, port string) string {
	if bindIP == "" {
		return ":" + port
	}
	// Check if it's IPv6
	if strings.Contains(bindIP, ":") {
		return "[" + bindIP + "]:" + port
	}
	return bindIP + ":" + port
}

func runRelay() {
	bindIP, bindPort := parseBindAddress(*port)
	bindAddr := makeBindAddress(bindIP, bindPort)

	listener, err := createReusableListener("tcp", bindAddr)
	if err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay server listening on %s", bindAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleRelayConnection(conn, bindIP)
	}
}

// closeCurrentSession closes the current active session and all its listeners
func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	if currentRelaySession != nil {
		currentRelaySession.mu.Lock()
		log.Printf("Closing previous session to allow immediate reconnection...")

		// Close all listeners first to free up ports
		for _, l := range currentRelaySession.listeners {
			l.Close()
		}
		currentRelaySession.listeners = nil

		// Close the session
		if currentRelaySession.session != nil && !currentRelaySession.session.IsClosed() {
			currentRelaySession.session.Close()
		}
		currentRelaySession.mu.Unlock()

		currentRelaySession = nil
		log.Printf("Previous session closed, ports freed")
	}
}

// setCurrentSession sets the current active session
func setCurrentSession(session *smux.Session) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	currentRelaySession = &ActiveRelaySession{
		session:   session,
		listeners: make([]io.Closer, 0),
	}
	return currentRelaySession
}

// addListener adds a listener to the current session for cleanup tracking
func (ars *ActiveRelaySession) addListener(l io.Closer) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(conn net.Conn, bindIP string) {
	defer conn.Close()

	// Disable Nagle's algorithm on tunnel connection for lower latency
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Authenticate: read exact token length
	tokLen := len(*token)
	tokBuf := make([]byte, tokLen)
	if _, err := io.ReadFull(conn, tokBuf); err != nil {
		log.Printf("Auth read error from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if string(tokBuf) != *token {
		log.Printf("Authentication failed from %s", conn.RemoteAddr())
		return
	}

	// Close any existing session BEFORE sending OK
	// This ensures ports are freed immediately for the new connection
	closeCurrentSession()

	// Send OK (2 bytes)
	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

	// Receive forward rules from VPN client
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		return
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)
	if ruleLen == 0 {
		log.Printf("No forward rules received from %s, connection idle", conn.RemoteAddr())
		return
	}

	ruleBuf := make([]byte, ruleLen)
	if _, err := io.ReadFull(conn, ruleBuf); err != nil {
		log.Printf("Failed to read forward rules: %v", err)
		return
	}

	// Parse received rules: "tcp_rules|udp_rules"
	parts := strings.Split(string(ruleBuf), "|")
	var forwardRules, forwardudpRules string
	if len(parts) >= 1 {
		forwardRules = parts[0]
	}
	if len(parts) >= 2 {
		forwardudpRules = parts[1]
	}
	log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)

	// Create smux session with optimized config to reduce latency
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024  // 4MB receive buffer
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024   // 1MB per stream
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	// Register this session as the current active session
	activeSession := setCurrentSession(session)

	// Parse forward rules with bind IP
	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD, bindIP)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD, bindIP)

	// WaitGroup to track all forwarder goroutines for clean shutdown
	var forwarderWg sync.WaitGroup

	// Start TCP forwarders
	for _, rule := range tcpRules {
		listener, err := createReusableListener("tcp", rule.bindAddr)
		if err != nil {
			log.Printf("Failed to listen on TCP %s: %v", rule.bindAddr, err)
			continue
		}
		activeSession.addListener(listener)

		forwarderWg.Add(1)
		go func(r ForwardRule, l net.Listener) {
			defer forwarderWg.Done()
			startTCPForwarderWithListener(session, r, l)
		}(rule, listener)
	}

	// Start UDP forwarders
	for _, rule := range udpRules {
		addr, err := net.ResolveUDPAddr("udp", rule.bindAddr)
		if err != nil {
			log.Printf("Failed to resolve UDP address %s: %v", rule.bindAddr, err)
			continue
		}
		udpConn, err := createReusableUDPListener(addr)
		if err != nil {
			log.Printf("Failed to listen on UDP %s: %v", rule.bindAddr, err)
			continue
		}
		activeSession.addListener(udpConn)

		forwarderWg.Add(1)
		go func(r ForwardRule, c *net.UDPConn) {
			defer forwarderWg.Done()
			startUDPForwarderWithConn(session, r, c)
		}(rule, udpConn)
	}

	// Keep connection alive while session is active
	for !session.IsClosed() {
		time.Sleep(1 * time.Second)
	}

	// Wait for all forwarder goroutines to finish
	forwarderWg.Wait()

	log.Printf("Session closed")
}

func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.bindAddr, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !session.IsClosed() {
				log.Printf("TCP accept error on %s: %v", rule.bindAddr, err)
			}
			return
		}

		go func(c net.Conn) {
			defer c.Close()

			// Disable Nagle's algorithm for lower latency
			if tcpConn, ok := c.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}

			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for TCP forward: %v", err)
				return
			}
			defer stream.Close()

			// Send forward header
			header := []byte{TCP_FORWARD}
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				log.Printf("Target port string too long: %s", rule.targetPort)
				return
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write header to stream: %v", err)
				return
			}

			// Bidirectional copy
			bidirectionalCopy(c, stream)
		}(conn)
	}
}

// bidirectionalCopy performs a full-duplex copy between two ReadWriteClosers.
// When one direction hits an error/EOF, it closes the other side's read to
// unblock the peer goroutine, then waits for both to finish.
func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		// Signal the other direction to stop by closing the reader's side
		closeOnDone.Close()
	}

	go copyDir(b, a, b) // a→b; on EOF close b
	go copyDir(a, b, a) // b→a; on EOF close a

	wg.Wait()
}

func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.bindAddr, rule.targetPort)

	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.Mutex

	// Cleanup stale sessions
	stopCleanup := make(chan struct{})
	var cleanupWg sync.WaitGroup
	cleanupWg.Add(1)
	go func() {
		defer cleanupWg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCleanup:
				return
			case <-ticker.C:
				sessionsMu.Lock()
				now := time.Now()
				for key, sess := range sessions {
					sess.mu.Lock()
					if now.Sub(sess.lastActive) > 2*time.Minute && !sess.closed {
						sess.closed = true
						sess.stream.Close()
						delete(sessions, key)
					}
					sess.mu.Unlock()
				}
				sessionsMu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535) // max UDP payload
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		sessionKey := clientAddr.String()

		sessionsMu.Lock()
		sess, exists := sessions[sessionKey]
		sessionsMu.Unlock()

		if !exists {
			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for UDP client %s: %v", sessionKey, err)
				continue
			}

			// Send forward header
			header := []byte{UDP_FORWARD}
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				log.Printf("Target port string too long: %s", rule.targetPort)
				stream.Close()
				continue
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write UDP header: %v", err)
				stream.Close()
				continue
			}

			sess = &UDPSession{
				conn:       conn,
				stream:     stream,
				clientAddr: clientAddr,
				lastActive: time.Now(),
			}

			sessionsMu.Lock()
			sessions[sessionKey] = sess
			sessionsMu.Unlock()

			keyCopy := sessionKey
			go func(s *smux.Stream, udpSess *UDPSession, sessKey string) {
				defer func() {
					sessionsMu.Lock()
					if v, ok := sessions[sessKey]; ok && v == udpSess {
						delete(sessions, sessKey)
					}
					sessionsMu.Unlock()

					udpSess.mu.Lock()
					if !udpSess.closed {
						udpSess.closed = true
						s.Close()
					}
					udpSess.mu.Unlock()
				}()

				respBuf := make([]byte, 65535)
				lenBuf := make([]byte, 2)
				for {
					// Read length prefix
					if _, err := io.ReadFull(s, lenBuf); err != nil {
						return
					}
					length := binary.BigEndian.Uint16(lenBuf)
					if int(length) > len(respBuf) {
						return
					}

					// Read data
					if _, err := io.ReadFull(s, respBuf[:length]); err != nil {
						return
					}

					udpSess.mu.Lock()
					if udpSess.closed {
						udpSess.mu.Unlock()
						return
					}
					_, _ = udpSess.conn.WriteToUDP(respBuf[:length], udpSess.clientAddr)
					udpSess.lastActive = time.Now()
					udpSess.mu.Unlock()
				}
			}(stream, sess, keyCopy)
		}

		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			// Session was closed concurrently; next iteration will create a new one
			continue
		}
		sess.lastActive = time.Now()

		// Send data through stream with atomic length-prefixed write
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])
		if _, err := sess.stream.Write(frame); err != nil {
			sess.closed = true
			sess.stream.Close()
			sess.mu.Unlock()

			sessionsMu.Lock()
			if v, ok := sessions[sessionKey]; ok && v == sess {
				delete(sessions, sessionKey)
			}
			sessionsMu.Unlock()
			continue
		}
		sess.mu.Unlock()
	}

	// Cleanup: signal the cleanup goroutine to stop, then close all sessions
	close(stopCleanup)
	cleanupWg.Wait()

	sessionsMu.Lock()
	for key, sess := range sessions {
		sess.mu.Lock()
		if !sess.closed {
			sess.closed = true
			sess.stream.Close()
		}
		sess.mu.Unlock()
		delete(sessions, key)
	}
	sessionsMu.Unlock()

	log.Printf("UDP forwarder %s stopped", rule.bindAddr)
}

func runVPN() {
	// Validate strategy
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	// Parse multiple hosts
	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
	log.Printf("Strategy: %s", *strategy)

	forwardRules := *forward + "|" + *forwardudp

	manager := &RelayManager{
		relays:        make([]*RelayConnection, len(hosts)),
		token:         *token,
		forwardRules:  forwardRules,
		strategy:      *strategy,
		reconnectChan: make(chan string, len(hosts)),
		bindIP:        "", // VPN client always binds to localhost
	}

	// Initialize relay connections
	for i, h := range hosts {
		manager.relays[i] = &RelayConnection{
			host: h,
		}
	}

	// Start connection manager
	var wg sync.WaitGroup
	for _, relay := range manager.relays {
		wg.Add(1)
		go func(r *RelayConnection) {
			defer wg.Done()
			manager.maintainConnection(r)
		}(relay)
	}

	// Monitor and manage active relay
	go manager.monitorRelays()

	// Wait for all connection goroutines
	wg.Wait()
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	for {
		log.Printf("[%s] Connecting to relay server...", relay.host)

		conn, err := net.DialTimeout("tcp", relay.host, 10*time.Second)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in 2s...", relay.host, err)
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Disable Nagle's algorithm on tunnel connection for lower latency
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		// Authenticate: send token and expect "OK"
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Authentication failed or bad response: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Send forward rules
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		ruleLen := make([]byte, 2)
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := conn.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send forward rules length: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := conn.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send forward rules: %v", relay.host, err)
				conn.Close()
				relay.connected.Store(false)
				time.Sleep(2 * time.Second)
				continue
			}
		}

		// Clear deadline after handshake; smux manages its own keepalive
		conn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated", relay.host)

		// Create smux session with optimized config
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024  // 4MB receive buffer
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024   // 1MB per stream
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second

		session, err := smux.Client(conn, smuxConfig)
		if err != nil {
			log.Printf("[%s] Failed to create smux session: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		// Update relay state atomically
		relay.mu.Lock()
		relay.conn = conn
		relay.session = session
		relay.lastCheck = time.Now()
		relay.connected.Store(true)
		relay.mu.Unlock()

		// Notify that this relay is ready
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		// Handle VPN session (blocking until session closed)
		rm.handleVPNSession(relay, session)

		// Connection lost — update state atomically
		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		session.Close()
		conn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

		// Notify monitor that we need to switch relays
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (rm *RelayManager) monitorRelays() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.checkAndSwitchRelay()
		case <-rm.reconnectChan:
			rm.checkAndSwitchRelay()
		}
	}
}

// sessionIsClosed checks if the relay's session is closed while holding the lock
// for the entire duration to prevent TOCTOU races.
func (r *RelayConnection) sessionIsClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session == nil {
		return true
	}
	return r.session.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		// Multi strategy: all connected relays should be active
		for _, relay := range rm.relays {
			sessClosed := relay.sessionIsClosed()
			if relay.connected.Load() && !sessClosed {
				if !relay.active.Load() {
					relay.active.Store(true)
					log.Printf("[%s] Marked as ACTIVE (multi strategy)", relay.host)
				}
			} else {
				if relay.active.Load() {
					relay.active.Store(false)
					log.Printf("[%s] Marked as INACTIVE (disconnected)", relay.host)
				}
			}
		}
		return
	}

	// Failover strategy: only one relay should be active
	currentActive := rm.activeRelay.Load()
	var currentRelay *RelayConnection
	if currentActive != nil {
		currentRelay = currentActive.(*RelayConnection)
	}

	// Check if current active relay is still connected
	if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.sessionIsClosed() {
		// Current relay is healthy, no need to switch
		return
	}

	// Need to find a new active relay
	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked as inactive", currentRelay.host)
	}

	// Find first connected relay
	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.sessionIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}

	// No relay available
	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available, waiting for reconnection...")
	}
}

func (rm *RelayManager) handleVPNSession(relay *RelayConnection, session *smux.Session) {
	var streamWg sync.WaitGroup
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			break
		}

		streamWg.Add(1)
		go func(s *smux.Stream) {
			defer streamWg.Done()
			defer s.Close()

			// Read header
			header := make([]byte, 2)
			if _, err := io.ReadFull(s, header); err != nil {
				return
			}

			proto := header[0]
			portLen := header[1]
			if portLen == 0 {
				return
			}
			portBuf := make([]byte, portLen)
			if _, err := io.ReadFull(s, portBuf); err != nil {
				return
			}

			targetPort := string(portBuf)

			// In failover mode, only process if this relay is active
			// In multi mode, all connected relays process traffic
			if !relay.active.Load() {
				return
			}

			if proto == TCP_FORWARD {
				handleTCPStream(s, targetPort)
			} else if proto == UDP_FORWARD {
				handleUDPStream(s, targetPort)
			}
		}(stream)
	}

	// Wait for all in-flight streams to drain before returning
	streamWg.Wait()
}

func handleTCPStream(stream *smux.Stream, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	// Disable Nagle's algorithm for lower latency
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	bidirectionalCopy(stream, target)
}

func handleUDPStream(stream *smux.Stream, targetPort string) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to resolve UDP target %s: %v", targetPort, err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("Failed to dial UDP target %s: %v", targetPort, err)
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Read from stream, write to UDP
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				conn.Close()
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				conn.Close()
				return
			}
			if _, err := io.ReadFull(stream, buf[:length]); err != nil {
				conn.Close()
				return
			}
			if _, err := conn.Write(buf[:length]); err != nil {
				return
			}
		}
	}()

	// Read from UDP, write to stream with atomic length-prefixed frame
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				stream.Close()
				return
			}
			// Build a single frame: [2-byte length][payload]
			frame := make([]byte, 2+n)
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			copy(frame[2:], buf[:n])
			if _, err := stream.Write(frame); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func parseForwardRules(rules string, proto int, bindIP string) []ForwardRule {
	if rules == "" {
		return nil
	}

	var result []ForwardRule
	pairs := strings.Split(rules, ";")
	for _, pair := range pairs {
		parts := strings.Split(pair, ",")
		if len(parts) == 2 {
			src := strings.TrimSpace(parts[0])
			tgt := strings.TrimSpace(parts[1])
			if src == "" || tgt == "" {
				continue
			}
			
			// Build bind address
			bindAddr := makeBindAddress(bindIP, src)
			
			result = append(result, ForwardRule{
				srcPort:    src,
				targetPort: tgt,
				proto:      proto,
				bindAddr:   bindAddr,
			})
		}
	}
	return result
}

// createReusableListener creates a TCP listener with SO_REUSEADDR set.
// SO_REUSEPORT is attempted on a best-effort basis and its failure is ignored,
// ensuring this works on all platforms.
func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
				// Best-effort: ignore REUSEPORT errors (unsupported on some platforms)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return setErr
		},
	}
	return lc.Listen(nil, network, address)
}

// createReusableUDPListener creates a UDP listener with SO_REUSEADDR set.
// SO_REUSEPORT is attempted on a best-effort basis.
func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
				// Best-effort: ignore REUSEPORT errors
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return setErr
		},
	}
	conn, err := lc.ListenPacket(nil, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
