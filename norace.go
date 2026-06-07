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
	TCP_FORWARD   = 1
	UDP_FORWARD   = 2
	SO_REUSEPORT  = 15 // Linux SO_REUSEPORT
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
	port       = flag.String("port", "", "Relay server port")
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

/* --------------------------------------------------------------
   Utility helpers
   --------------------------------------------------------------*/

// writeAll guarantees that the entire slice is written to w.
// It loops until all bytes are sent or an error occurs.
func writeAll(w io.Writer, p []byte) error {
	for written := 0; written < len(p); {
		n, err := w.Write(p[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

/* --------------------------------------------------------------
   Relay (server) side
   --------------------------------------------------------------*/

func runRelay() {
	listener, err := createReusableListener("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay server listening on :%s", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleRelayConnection(conn)
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

// Relay connection handling --------------------------------------------------

func handleRelayConnection(conn net.Conn) {
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
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // 4MB receive buffer
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024  // 1MB per stream
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	// The session will be closed when this function returns
	defer session.Close()

	// Register this session as the current active session
	activeSession := setCurrentSession(session)

	// Parse forward rules
	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	// WaitGroup to track all forwarder goroutines for clean shutdown
	var forwarderWg sync.WaitGroup

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
			startTCPForwarderWithListener(session, r, l)
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
			startUDPForwarderWithConn(session, r, c)
		}(rule, udpConn)
	}

	// Keep connection alive while session is active
	for !session.IsClosed() {
		time.Sleep(1 * time.Second)
	}

	// -----------------------------------------------------------------
	// Session is now closed – clean up listeners *before* waiting for
	// forwarder goroutines to finish.  This unblocks their Accept/Read
	// loops.
	if activeSession != nil {
		// Avoid a race with a concurrently arriving client that may be
		// executing closeCurrentSession()
		currentRelaySessionMu.Lock()
		activeSession.mu.Lock()
		for _, l := range activeSession.listeners {
			_ = l.Close()
		}
		activeSession.listeners = nil
		activeSession.mu.Unlock()
		currentRelaySessionMu.Unlock()
	}
	// -----------------------------------------------------------------

	// Wait for all forwarder goroutines to finish
	forwarderWg.Wait()

	log.Printf("Session closed")
}

// -----------------------------------------------------------------
// TCP forwarder (per listening socket)
// -----------------------------------------------------------------
func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		// Bail out early if the tunnel is already closed – prevents a
		// blocked Accept that would otherwise wait forever.
		if session.IsClosed() {
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			if !session.IsClosed() {
				log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
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
			if err := writeAll(stream, header); err != nil {
				log.Printf("Failed to write header to stream: %v", err)
				return
			}

			// Bidirectional copy
			bidirectionalCopy(c, stream)
		}(conn)
	}
}

// -----------------------------------------------------------------
// UDP forwarder (per listening socket)
// -----------------------------------------------------------------
func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	// Map of client address -> UDP session (one stream per client)
	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.Mutex

	// -----------------------------------------------------------------
	// Periodic cleanup of idle UDP sessions
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

	// -----------------------------------------------------------------
	// Main UDP read loop
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // conn closed or error – exit loop
		}

		sessionKey := clientAddr.String()

		sessionsMu.Lock()
		sess, exists := sessions[sessionKey]
		sessionsMu.Unlock()

		if !exists {
			// No stream yet for this client – create one
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
			if err := writeAll(stream, header); err != nil {
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

			// Goroutine that reads from the smux stream and pushes data back to the client
			keyCopy := sessionKey
			go func(s *smux.Stream, udpSess *UDPSession, sessKey string) {
				defer func() {
					// Remove from sessions map
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
					// Read payload
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

		// At this point we have a stream for the client – forward the packet
		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			continue
		}
		sess.lastActive = time.Now()

		// Length‑prefixed frame to send to the remote side
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])

		if err := writeAll(sess.stream, frame); err != nil {
			// On error clean up the per‑client session
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

	// -----------------------------------------------------------------
	// Cleanup routine: stop periodic idle‑session cleaner & close everything
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

	log.Printf("UDP forwarder %s stopped", rule.srcPort)
}

// -----------------------------------------------------------------
// Helper for full‑duplex copy (TCP)
// -----------------------------------------------------------------
func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		// Signal the opposite side that we are done
		closeOnDone.Close()
	}

	go copyDir(b, a, b) // a→b
	go copyDir(a, b, a) // b→a

	wg.Wait()
}

// -----------------------------------------------------------------
// VPN (client) side
// -----------------------------------------------------------------
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
	}

	// Initialise relay structs
	for i, h := range hosts {
		manager.relays[i] = &RelayConnection{
			host: h,
		}
	}

	// Spawn a goroutine for each relay that maintains its connection
	var wg sync.WaitGroup
	for _, relay := range manager.relays {
		wg.Add(1)
		go func(r *RelayConnection) {
			defer wg.Done()
			manager.maintainConnection(r)
		}(relay)
	}

	// Monitor active relay according to chosen strategy
	go manager.monitorRelays()

	// Wait for all connection‑maintaining goroutines (they run forever)
	wg.Wait()
}

// -----------------------------------------------------------------
// Relay manager helpers (VPN side)
// -----------------------------------------------------------------
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

		// Disable Nagle's algorithm
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		// Authenticate: send token, expect "OK"
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

		// Send forward‑rule payload
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

		// Clear deadline – smux has its own keep‑alive handling
		conn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated", relay.host)

		// Create smux session with tuned parameters
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // 4 MiB
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // 1 MiB
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

		// Update shared state atomically
		relay.mu.Lock()
		relay.conn = conn
		relay.session = session
		relay.lastCheck = time.Now()
		relay.connected.Store(true)
		relay.mu.Unlock()

		// Notify monitor that a new relay is ready
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		// Handle incoming streams from the relay (forwarded traffic)
		rm.handleVPNSession(relay, session)

		// Smux session closed – clean up
		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		session.Close()
		conn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

		// Notify monitor that we need to re‑evaluate the active relay
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

// monitorRelays watches the set of relays and selects the active one
// according to the configured strategy.
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

// sessionIsClosed safely checks whether the smux session is already closed.
func (r *RelayConnection) sessionIsClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session == nil {
		return true
	}
	return r.session.IsClosed()
}

// checkAndSwitchRelay selects the appropriate relay based on strategy.
func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		// All healthy relays stay active
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

	// ------- FAILOVER strategy -------
	currentActive := rm.activeRelay.Load()
	var currentRelay *RelayConnection
	if currentActive != nil {
		currentRelay = currentActive.(*RelayConnection)
	}

	// If the current active relay is still healthy, keep it.
	if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.sessionIsClosed() {
		return
	}
	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked as INACTIVE (failover)", currentRelay.host)
	}

	// Find the first healthy relay and promote it.
	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.sessionIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover)", relay.host)
			return
		}
	}
	// No relay available – keep the activeRelay nil.
	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available, waiting for reconnection...")
	}
}

// handleVPNSession processes inbound streams from the relay server.
func (rm *RelayManager) handleVPNSession(relay *RelayConnection, session *smux.Session) {
	var streamWg sync.WaitGroup

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// smux session closed – exit loop
			break
		}
		streamWg.Add(1)

		go func(s *smux.Stream) {
			defer streamWg.Done()
			defer s.Close()

			// Header: [proto][portLen][portBytes]
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

			// In failover mode only the currently active relay should process traffic.
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

	// Wait for all in‑flight streams to finish before returning.
	streamWg.Wait()
}

// -----------------------------------------------------------------
// TCP handling on the VPN side
// -----------------------------------------------------------------
func handleTCPStream(stream *smux.Stream, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	// Disable Nagle on the outbound side as well
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	bidirectionalCopy(stream, target)
}

// -----------------------------------------------------------------
// UDP handling on the VPN side
// -----------------------------------------------------------------
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

	// ------- read from UDP, write to stream -------
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				// any error (including timeout) ends the goroutine
				stream.Close()
				return
			}
			frame := make([]byte, 2+n)
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			copy(frame[2:], buf[:n])
			if err := writeAll(stream, frame); err != nil {
				return
			}
		}
	}()

	// ------- read from stream, write to UDP -------
	go func() {
		defer wg.Done()
		respBuf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		for {
			// length prefix
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(respBuf) {
				return
			}
			if _, err := io.ReadFull(stream, respBuf[:length]); err != nil {
				return
			}
			if _, err := conn.Write(respBuf[:length]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// -----------------------------------------------------------------
// Parsing helpers
// -----------------------------------------------------------------
func parseForwardRules(rules string, proto int) []ForwardRule {
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
			result = append(result, ForwardRule{
				srcPort:    src,
				targetPort: tgt,
				proto:      proto,
			})
		}
	}
	return result
}

// -----------------------------------------------------------------
// OS‑specific listener helpers (SO_REUSEADDR + best‑effort SO_REUSEPORT)
// -----------------------------------------------------------------
func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
				// best‑effort reuse‑port – ignore errors on platforms that lack it
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return setErr
		},
	}
	return lc.Listen(nil, network, address)
}

// UDP version of the reusable listener
func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
				// best‑effort reuse‑port
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return setErr
		},
	}
	pc, err := lc.ListenPacket(nil, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
