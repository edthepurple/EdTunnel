package main

import (
	"context"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
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
	SO_REUSEPORT = 15 // Linux SO_REUSEPORT (fallback; may vary by OS)
)

type ForwardRule struct {
	srcPort    string
	targetPort string
	proto      int
}

type UDPSession struct {
	conn       *net.UDPConn
	stream     *smux.Stream
	clientAddr *net.UDPAddr
	lastActive time.Time
	closed     bool // Track if this session has been closed
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
	activeRelay   *RelayConnection // Protected by mu
	token         string
	forwardRules  string
	strategy      string // "multi" or "failover"
	reconnectChan chan string
	mu            sync.RWMutex
}

// ActiveRelaySession tracks the current active session on the relay server
// to allow immediate cleanup when a VPN client reconnects
type ActiveRelaySession struct {
	session   *smux.Session
	listeners []io.Closer
	cancel    context.CancelFunc // For cancelling all goroutines
	closed    bool               // Track if already closed - protected by mu
	mu        sync.Mutex
}

var (
	mode       = flag.String("mode", "", "Mode: relay or vpn")
	port       = flag.String("port", "", "Relay server port")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")

	// Track current relay session for immediate cleanup on VPN reconnection
	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex

	// Buffer pool for reducing allocations in hot paths
	// FIX #1: Store pointers properly to avoid slice header copying issues
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024) // 32KB buffers
			return &buf
		},
	}
)

// FIX #1: Return pointer to slice to maintain proper pool semantics
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// FIX #1: Accept pointer to slice to return the same pointer to the pool
func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received, cleaning up...")
		cancel()
	}()

	if *mode == "relay" {
		if *port == "" {
			log.Fatal("Port is required for relay mode")
		}
		runRelay(ctx)
	} else if *mode == "vpn" {
		if *host == "" {
			log.Fatal("Host is required for vpn mode")
		}
		runVPN(ctx)
	} else {
		log.Fatal("Invalid mode. Use 'relay' or 'vpn'")
	}
}

func runRelay(ctx context.Context) {
	listener, err := createReusableListener("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay server listening on :%s", *port)

	// Close listener on context cancellation
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Println("Relay server shutting down")
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go handleRelayConnection(ctx, conn)
	}
}

// closeCurrentSession closes the current active session and all its listeners
// This is idempotent and safe to call multiple times
func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	if currentRelaySession == nil {
		return
	}

	// FIX #4: Use mutex to protect closed flag and ensure atomic close operation
	currentRelaySession.mu.Lock()

	if currentRelaySession.closed {
		// Already closed by another goroutine
		currentRelaySession.mu.Unlock()
		currentRelaySession = nil
		return
	}

	currentRelaySession.closed = true

	log.Printf("Closing previous session to allow immediate reconnection...")

	// Cancel context first to signal all goroutines to stop
	if currentRelaySession.cancel != nil {
		currentRelaySession.cancel()
	}

	// Close all listeners to free up ports
	for _, l := range currentRelaySession.listeners {
		if l != nil {
			l.Close()
		}
	}
	currentRelaySession.listeners = nil

	// Close the session last
	if currentRelaySession.session != nil && !currentRelaySession.session.IsClosed() {
		currentRelaySession.session.Close()
	}
	currentRelaySession.mu.Unlock()

	currentRelaySession = nil
	log.Printf("Previous session closed, ports freed")
}

// setCurrentSession sets the current active session
func setCurrentSession(session *smux.Session, cancel context.CancelFunc) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	currentRelaySession = &ActiveRelaySession{
		session:   session,
		listeners: make([]io.Closer, 0, 8),
		cancel:    cancel,
		closed:    false,
	}
	return currentRelaySession
}

// addListener adds a listener to the current session for cleanup tracking
// FIX #4: Check closed flag under mutex to prevent race with closeCurrentSession
func (ars *ActiveRelaySession) addListener(l io.Closer) {
	ars.mu.Lock()
	defer ars.mu.Unlock()

	// Don't add if already closed
	if ars.closed {
		l.Close()
		return
	}
	ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(parentCtx context.Context, conn net.Conn) {
	defer conn.Close()

	// Disable Nagle's algorithm on tunnel connection for lower latency
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Set read deadline for authentication
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	// Close any existing session BEFORE sending OK
	// This ensures ports are freed immediately for the new connection
	closeCurrentSession()

	// Send OK (2 bytes)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", conn.RemoteAddr(), err)
		return
	}
	conn.SetWriteDeadline(time.Time{})

	log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

	// Receive forward rules from VPN client
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		return
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)

	var forwardRules, forwardudpRules string
	if ruleLen > 0 {
		ruleBuf := make([]byte, ruleLen)
		if _, err := io.ReadFull(conn, ruleBuf); err != nil {
			log.Printf("Failed to read forward rules: %v", err)
			return
		}

		// Parse received rules: "tcp_rules|udp_rules"
		parts := strings.Split(string(ruleBuf), "|")
		if len(parts) >= 1 {
			forwardRules = parts[0]
		}
		if len(parts) >= 2 {
			forwardudpRules = parts[1]
		}
		log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)
	}
	conn.SetReadDeadline(time.Time{})

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

	// Create context for this session's goroutines
	sessionCtx, sessionCancel := context.WithCancel(parentCtx)
	defer sessionCancel()

	// Register this session as the current active session
	activeSession := setCurrentSession(session, sessionCancel)

	// WaitGroup to track all forwarder goroutines
	var forwarderWg sync.WaitGroup

	// Parse forward rules
	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	// Start TCP forwarders
	for _, rule := range tcpRules {
		listener, err := createReusableListener("tcp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(listener)

		forwarderWg.Add(1)
		go func(r ForwardRule, l net.Listener) {
			defer forwarderWg.Done()
			startTCPForwarderWithListener(sessionCtx, session, r, l)
		}(rule, listener)
	}

	// Start UDP forwarders
	for _, rule := range udpRules {
		addr, err := net.ResolveUDPAddr("udp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to resolve UDP address %s: %v", rule.srcPort, err)
			continue
		}
		udpConn, err := createReusableUDPListener(addr)
		if err != nil {
			log.Printf("Failed to listen on UDP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(udpConn)

		forwarderWg.Add(1)
		go func(r ForwardRule, c *net.UDPConn) {
			defer forwarderWg.Done()
			startUDPForwarderWithConn(sessionCtx, session, r, c)
		}(rule, udpConn)
	}

	// Wait for session to close or context cancellation
	select {
	case <-sessionCtx.Done():
		session.Close()
	case <-waitSessionClosed(session):
	}

	// Wait for all forwarders to finish
	forwarderWg.Wait()

	log.Printf("Session closed for %s", conn.RemoteAddr())
}

// waitSessionClosed returns a channel that closes when the session is closed
func waitSessionClosed(session *smux.Session) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		// Use AcceptStream as a blocking wait - it returns error when session closes
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			// We shouldn't get streams on the server side in this design,
			// but handle gracefully
			stream.Close()
		}
	}()
	return ch
}

func startTCPForwarderWithListener(ctx context.Context, session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	// WaitGroup for tracking active connections
	var connWg sync.WaitGroup
	defer connWg.Wait()

	// Accept loop
	for {
		// Check context before accepting
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set accept deadline to allow checking context
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Check context and retry
			}
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
				return
			}
		}

		connWg.Add(1)
		go func(c net.Conn) {
			defer connWg.Done()
			handleTCPForwardConnection(ctx, session, c, rule.targetPort)
		}(conn)
	}
}

func handleTCPForwardConnection(ctx context.Context, session *smux.Session, c net.Conn, targetPort string) {
	defer c.Close()

	// Disable Nagle's algorithm for lower latency
	if tcpConn, ok := c.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Check if session is closed before opening stream
	if session.IsClosed() {
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream for TCP forward: %v", err)
		return
	}
	defer stream.Close()

	// Send forward header
	header := make([]byte, 0, 2+len(targetPort))
	header = append(header, TCP_FORWARD)
	portBytes := []byte(targetPort)
	if len(portBytes) > 255 {
		log.Printf("Target port string too long: %s", targetPort)
		return
	}
	header = append(header, byte(len(portBytes)))
	header = append(header, portBytes...)
	if _, err := stream.Write(header); err != nil {
		log.Printf("Failed to write header to stream: %v", err)
		return
	}

	// Bidirectional copy with context awareness
	bidirectionalCopy(ctx, c, stream)
}

// bidirectionalCopy copies data between two connections with proper cleanup
// FIX #2: Properly handle goroutine cleanup to prevent leaks
func bidirectionalCopy(ctx context.Context, conn net.Conn, stream *smux.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel to signal that copying is done (for cleanup goroutine)
	copyDone := make(chan struct{})

	// conn to stream
	go func() {
		defer wg.Done()
		bufPtr := getBuffer()
		defer putBuffer(bufPtr)
		buf := *bufPtr
		for {
			select {
			case <-ctx.Done():
				return
			case <-copyDone:
				return
			default:
			}

			// Set read deadline to allow context checking
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				stream.Close() // Signal the other direction
				return
			}
			if n > 0 {
				stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := stream.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}()

	// stream to conn
	go func() {
		defer wg.Done()
		bufPtr := getBuffer()
		defer putBuffer(bufPtr)
		buf := *bufPtr
		for {
			select {
			case <-ctx.Done():
				return
			case <-copyDone:
				return
			default:
			}

			n, err := stream.Read(buf)
			if err != nil {
				conn.Close() // Signal the other direction
				return
			}
			if n > 0 {
				conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}()

	// FIX #2: Cleanup goroutine that exits when either context is cancelled OR copies finish
	go func() {
		select {
		case <-ctx.Done():
		case <-copyDone:
		}
		conn.Close()
		stream.Close()
	}()

	wg.Wait()
	close(copyDone) // Signal cleanup goroutine to exit if it hasn't already
}

func startUDPForwarderWithConn(ctx context.Context, session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.Mutex

	// Cleanup goroutine with proper shutdown
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				sessionsMu.Lock()
				for key, sess := range sessions {
					sess.mu.Lock()
					inactive := now.Sub(sess.lastActive) > 2*time.Minute
					alreadyClosed := sess.closed
					sess.mu.Unlock()

					if inactive && !alreadyClosed {
						sess.mu.Lock()
						if !sess.closed {
							sess.closed = true
							sess.stream.Close()
						}
						sess.mu.Unlock()
						delete(sessions, key)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	// WaitGroup for response reader goroutines
	var readerWg sync.WaitGroup
	defer func() {
		// Wait for cleanup goroutine
		<-cleanupDone

		// Close all remaining sessions
		sessionsMu.Lock()
		for _, sess := range sessions {
			sess.mu.Lock()
			if !sess.closed {
				sess.closed = true
				sess.stream.Close()
			}
			sess.mu.Unlock()
		}
		sessionsMu.Unlock()

		// Wait for all reader goroutines
		readerWg.Wait()
	}()

	buf := make([]byte, 65535) // Max UDP payload
	for {
		// Check context
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline to allow context checking
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("UDP read error on %s: %v", rule.srcPort, err)
				return
			}
		}

		sessionKey := clientAddr.String()

		sessionsMu.Lock()
		sess, exists := sessions[sessionKey]
		if exists {
			// Check if session is still valid
			sess.mu.Lock()
			if sess.closed {
				exists = false
			}
			sess.mu.Unlock()
		}

		if !exists {
			if session.IsClosed() {
				sessionsMu.Unlock()
				return
			}

			stream, err := session.OpenStream()
			if err != nil {
				sessionsMu.Unlock()
				log.Printf("Failed to open stream for UDP client %s: %v", sessionKey, err)
				continue
			}

			// Send forward header
			header := make([]byte, 0, 2+len(rule.targetPort))
			header = append(header, UDP_FORWARD)
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				sessionsMu.Unlock()
				log.Printf("Target port string too long: %s", rule.targetPort)
				stream.Close()
				continue
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				sessionsMu.Unlock()
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
			sessions[sessionKey] = sess

			// Start response reader goroutine
			readerWg.Add(1)
			go func(s *UDPSession, sessKey string) {
				defer readerWg.Done()
				readUDPResponses(ctx, s, sessKey, sessions, &sessionsMu)
			}(sess, sessionKey)
		}
		sessionsMu.Unlock()

		// Send data through stream with length prefix
		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			continue
		}
		sess.lastActive = time.Now()

		// FIX #6: Log oversized UDP packets instead of silently dropping
		if n > 65535 {
			log.Printf("UDP packet too large (%d bytes) from %s, dropping", n, clientAddr)
			sess.mu.Unlock()
			continue
		}

		// Write length prefix and data atomically (relative to this session)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))

		// Use writev-style write to reduce syscalls
		combined := make([]byte, 2+n)
		copy(combined, lenBuf)
		copy(combined[2:], buf[:n])

		if _, err := sess.stream.Write(combined); err != nil {
			sess.closed = true
			sess.stream.Close()
			sess.mu.Unlock()

			sessionsMu.Lock()
			delete(sessions, sessionKey)
			sessionsMu.Unlock()
			continue
		}
		sess.mu.Unlock()
	}
}

// FIX #5: readUDPResponses - consistent lock ordering (session.mu first, then sessionsMu)
func readUDPResponses(ctx context.Context, session *UDPSession, sessKey string,
	sessions map[string]*UDPSession, sessionsMu *sync.Mutex) {

	respBuf := make([]byte, 65535)
	lenBuf := make([]byte, 2)

	defer func() {
		session.mu.Lock()
		if !session.closed {
			session.closed = true
			session.stream.Close()
		}
		session.mu.Unlock()

		sessionsMu.Lock()
		if v, ok := sessions[sessKey]; ok && v == session {
			delete(sessions, sessKey)
		}
		sessionsMu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read length prefix
		if _, err := io.ReadFull(session.stream, lenBuf); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(lenBuf)
		if int(length) > len(respBuf) {
			log.Printf("UDP response too large (%d bytes), closing session", length)
			return
		}

		// Read data
		if _, err := io.ReadFull(session.stream, respBuf[:length]); err != nil {
			return
		}

		session.mu.Lock()
		if session.closed {
			session.mu.Unlock()
			return
		}
		session.lastActive = time.Now()
		_, _ = session.conn.WriteToUDP(respBuf[:length], session.clientAddr)
		session.mu.Unlock()
	}
}

func runVPN(ctx context.Context) {
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
			manager.maintainConnection(ctx, r)
		}(relay)
	}

	// Monitor and manage active relay
	wg.Add(1)
	go func() {
		defer wg.Done()
		manager.monitorRelays(ctx)
	}()

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("VPN client shutting down...")

	// Close all relay connections
	manager.mu.Lock()
	for _, relay := range manager.relays {
		relay.mu.Lock()
		if relay.session != nil && !relay.session.IsClosed() {
			relay.session.Close()
		}
		if relay.conn != nil {
			relay.conn.Close()
		}
		relay.mu.Unlock()
	}
	manager.mu.Unlock()

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("VPN client shutdown complete")
	case <-time.After(5 * time.Second):
		log.Println("VPN client shutdown timed out")
	}
}

func (rm *RelayManager) maintainConnection(ctx context.Context, relay *RelayConnection) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[%s] Connecting to relay server...", relay.host)

		// Dial with timeout
		dialer := net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", relay.host)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in 2s...", relay.host, err)
			relay.connected.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Disable Nagle's algorithm on tunnel connection for lower latency
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		// Authenticate with timeout
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Authentication failed or bad response: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Reset deadlines
		conn.SetReadDeadline(time.Time{})
		conn.SetWriteDeadline(time.Time{})

		// Send forward rules
		ruleLen := make([]byte, 2)
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			conn.Close()
			relay.connected.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := conn.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send forward rules length: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := conn.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send forward rules: %v", relay.host, err)
				conn.Close()
				relay.connected.Store(false)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
		}
		conn.SetWriteDeadline(time.Time{})

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
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// Update relay state atomically
		relay.mu.Lock()
		relay.conn = conn
		relay.session = session
		relay.lastCheck = time.Now()
		relay.mu.Unlock()
		relay.connected.Store(true)

		// Notify that this relay is ready
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		// Handle VPN session (blocking until session closed or context cancelled)
		rm.handleVPNSession(ctx, relay, session)

		// Connection lost - update state
		relay.active.Store(false)
		relay.connected.Store(false)

		relay.mu.Lock()
		if relay.session != nil && !relay.session.IsClosed() {
			relay.session.Close()
		}
		if relay.conn != nil {
			relay.conn.Close()
		}
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

		// Notify monitor that we need to switch relays
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (rm *RelayManager) monitorRelays(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.checkAndSwitchRelay()
		case <-rm.reconnectChan:
			rm.checkAndSwitchRelay()
		}
	}
}

func (r *RelayConnection) sessionIsClosed() bool {
	r.mu.Lock()
	sess := r.session
	r.mu.Unlock()
	if sess == nil {
		return true
	}
	return sess.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		// Multi strategy: all connected relays should be active
		for _, relay := range rm.relays {
			sessClosed := relay.sessionIsClosed()
			isConnected := relay.connected.Load()

			if isConnected && !sessClosed {
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
	currentRelay := rm.activeRelay

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
			rm.activeRelay = relay
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}

	rm.activeRelay = nil

	// No relay available
	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available, waiting for reconnection...")
	}
}

func (rm *RelayManager) handleVPNSession(ctx context.Context, relay *RelayConnection, session *smux.Session) {
	var wg sync.WaitGroup
	defer wg.Wait()

	// Accept streams until session closes or context is cancelled
	for {
		select {
		case <-ctx.Done():
			session.Close()
			return
		default:
		}

		stream, err := session.AcceptStream()
		if err != nil {
			return
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()
			defer s.Close()

			// Read header with timeout
			header := make([]byte, 2)
			s.SetReadDeadline(time.Now().Add(10 * time.Second))
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
			s.SetReadDeadline(time.Time{})

			targetPort := string(portBuf)

			// In failover mode, only process if this relay is active
			// In multi mode, all connected relays process traffic
			if !relay.active.Load() {
				return
			}

			if proto == TCP_FORWARD {
				handleTCPStream(ctx, s, targetPort)
			} else if proto == UDP_FORWARD {
				handleUDPStream(ctx, s, targetPort)
			}
		}(stream)
	}
}

func handleTCPStream(ctx context.Context, stream *smux.Stream, targetPort string) {
	// Dial with timeout
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	// Disable Nagle's algorithm for lower latency
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	bidirectionalCopy(ctx, target, stream)
}

// FIX #3: handleUDPStream - properly handle goroutine cleanup to prevent leaks
func handleUDPStream(ctx context.Context, stream *smux.Stream, targetPort string) {
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

	// Channel to signal that processing is done (for cleanup goroutine)
	processingDone := make(chan struct{})

	// Channel for coordinated shutdown between read/write goroutines
	done := make(chan struct{})
	var doneOnce sync.Once

	closeDone := func() {
		doneOnce.Do(func() {
			close(done)
		})
	}

	// Read from stream, write to UDP
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		for {
			select {
			case <-ctx.Done():
				closeDone()
				return
			case <-done:
				return
			default:
			}

			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				closeDone()
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				closeDone()
				return
			}
			if _, err := io.ReadFull(stream, buf[:length]); err != nil {
				closeDone()
				return
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(buf[:length]); err != nil {
				closeDone()
				return
			}
		}
	}()

	// Read from UDP, write to stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				closeDone()
				return
			case <-done:
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				closeDone()
				return
			}
			if n > 65535 {
				closeDone()
				return
			}

			// Write length prefix and data
			combined := make([]byte, 2+n)
			binary.BigEndian.PutUint16(combined, uint16(n))
			copy(combined[2:], buf[:n])

			stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := stream.Write(combined); err != nil {
				closeDone()
				return
			}
		}
	}()

	// FIX #3: Cleanup goroutine that exits when either context is cancelled OR processing finishes
	go func() {
		select {
		case <-ctx.Done():
		case <-processingDone:
		}
		conn.Close()
		stream.Close()
	}()

	wg.Wait()
	close(processingDone) // Signal cleanup goroutine to exit if it hasn't already
}

func parseForwardRules(rules string, proto int) []ForwardRule {
	if rules == "" {
		return nil
	}

	var result []ForwardRule
	pairs := strings.Split(rules, ";")
	for _, pair := range pairs {
		parts := strings.Split(pair, ",")
		if len(parts) == 2 {
			result = append(result, ForwardRule{
				srcPort:    strings.TrimSpace(parts[0]),
				targetPort: strings.TrimSpace(parts[1]),
				proto:      proto,
			})
		}
	}
	return result
}

func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
					opErr = e
					return
				}
				// try to set REUSEPORT, ignore error if not supported
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}

func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
					opErr = e
					return
				}
				// try to set REUSEPORT, ignore error if not supported
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
