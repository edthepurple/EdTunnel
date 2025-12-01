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

var (
	mode       = flag.String("mode", "", "Mode: relay or vpn")
	port       = flag.String("port", "", "Relay server port")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")
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
		// empty rules permitted
	} else {
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

		// Parse forward rules
		tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
		udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

		// Track listeners for cleanup
		var listeners []io.Closer
		var listenersMu sync.Mutex

		// Start TCP forwarders
		for _, rule := range tcpRules {
			listener, err := createReusableListener("tcp", ":"+rule.srcPort)
			if err != nil {
				log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
				continue
			}
			listenersMu.Lock()
			listeners = append(listeners, listener)
			listenersMu.Unlock()

			go startTCPForwarderWithListener(session, rule, listener)
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
			listenersMu.Lock()
			listeners = append(listeners, udpConn)
			listenersMu.Unlock()

			go startUDPForwarderWithConn(session, rule, udpConn)
		}

		// Keep connection alive while session is active
		for !session.IsClosed() {
			time.Sleep(1 * time.Second)
		}

		// Cleanup all listeners
		log.Printf("Session closed, cleaning up listeners...")
		time.Sleep(100 * time.Millisecond) // Grace period for in-flight operations
		listenersMu.Lock()
		for _, l := range listeners {
			l.Close()
		}
		listenersMu.Unlock()
		log.Printf("Cleanup complete, ready for reconnection")
	}
}

func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
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

			// Bidirectional copy with small chunks to reduce latency
			var wg sync.WaitGroup
			wg.Add(2)

			// Client to stream
			go func() {
				defer wg.Done()
				buf := make([]byte, 16*1024) // 16KB chunks
				for {
					n, err := c.Read(buf)
					if err != nil {
						stream.Close()
						return
					}
					if n > 0 {
						if _, err := stream.Write(buf[:n]); err != nil {
							return
						}
					}
				}
			}()

			// Stream to client
			go func() {
				defer wg.Done()
				buf := make([]byte, 16*1024) // 16KB chunks
				for {
					n, err := stream.Read(buf)
					if err != nil {
						c.Close()
						return
					}
					if n > 0 {
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
				}
			}()

			wg.Wait()
		}(conn)
	}
}

func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.RWMutex

	// Cleanup stale sessions
	stopCleanup := make(chan struct{})
	go func() {
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
					if now.Sub(sess.lastActive) > 2*time.Minute {
						_ = sess.stream.Close()
						delete(sessions, key)
					}
					sess.mu.Unlock()
				}
				sessionsMu.Unlock()
			}
		}
	}()
	defer close(stopCleanup)

	buf := make([]byte, 16*1024) // 16KB
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Cleanup all sessions before exiting
			sessionsMu.Lock()
			for _, sess := range sessions {
				_ = sess.stream.Close()
			}
			sessionsMu.Unlock()
			log.Printf("UDP read error on %s: %v", rule.srcPort, err)
			return
		}

		sessionKey := clientAddr.String()

		sessionsMu.RLock()
		sess, exists := sessions[sessionKey]
		sessionsMu.RUnlock()

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
				_ = stream.Close()
				continue
			}
			header = append(header, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write UDP header: %v", err)
				_ = stream.Close()
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

			// Capture sessionKey for the goroutine to avoid loop-variable capture
			keyCopy := sessionKey
			go func(s *smux.Stream, session *UDPSession, sessKey string) {
				defer s.Close()
				respBuf := make([]byte, 16*1024)
				for {
					// Read length prefix
					lenBuf := make([]byte, 2)
					if _, err := io.ReadFull(s, lenBuf); err != nil {
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}
					length := binary.BigEndian.Uint16(lenBuf)
					if int(length) > len(respBuf) {
						// corrupted length, remove session and exit
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}

					// Read data
					if _, err := io.ReadFull(s, respBuf[:length]); err != nil {
						sessionsMu.Lock()
						if v, ok := sessions[sessKey]; ok && v == session {
							delete(sessions, sessKey)
						}
						sessionsMu.Unlock()
						return
					}

					session.mu.Lock()
					if _, err := session.conn.WriteToUDP(respBuf[:length], session.clientAddr); err != nil {
						// ignore write error (client might be gone); but update lastActive
					}
					session.lastActive = time.Now()
					session.mu.Unlock()
				}
			}(stream, sess, keyCopy)
		}

		sess.mu.Lock()
		sess.lastActive = time.Now()
		// Send data through stream with length prefix
		lenBuf := make([]byte, 2)
		if n > 65535 {
			// impossible for UDP payload here, but defensive
			sess.mu.Unlock()
			continue
		}
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		if _, err := sess.stream.Write(lenBuf); err != nil {
			// close and remove session
			_ = sess.stream.Close()
			deleteSessionSafe(&sessions, &sessionsMu, sessionKey)
			sess.mu.Unlock()
			continue
		}
		if _, err := sess.stream.Write(buf[:n]); err != nil {
			_ = sess.stream.Close()
			deleteSessionSafe(&sessions, &sessionsMu, sessionKey)
			sess.mu.Unlock()
			continue
		}
		sess.mu.Unlock()
	}
}

func deleteSessionSafe(sessions *map[string]*UDPSession, mu *sync.RWMutex, key string) {
	mu.Lock()
	if s, ok := (*sessions)[key]; ok {
		_ = s.stream.Close()
		delete(*sessions, key)
	}
	mu.Unlock()
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

		conn, err := net.Dial("tcp", relay.host)
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
		ruleLen := make([]byte, 2)
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
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

		// Update relay state
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

		// Handle VPN session (blocking until session closed)
		rm.handleVPNSession(relay, session)

		// Connection lost
		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
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
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}

		go func(s *smux.Stream) {
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
}

func handleTCPStream(stream *smux.Stream, targetPort string) {
	target, err := net.Dial("tcp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	// Disable Nagle's algorithm for lower latency
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream to target (from relay)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024) // 16KB chunks
		for {
			n, err := stream.Read(buf)
			if err != nil {
				target.Close()
				return
			}
			if n > 0 {
				if _, err := target.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}()

	// Target to stream (to relay)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024) // 16KB chunks
		for {
			n, err := target.Read(buf)
			if err != nil {
				stream.Close()
				return
			}
			if n > 0 {
				if _, err := stream.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
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
		buf := make([]byte, 16*1024)
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				return
			}
			if _, err := io.ReadFull(stream, buf[:length]); err != nil {
				return
			}
			if _, err := conn.Write(buf[:length]); err != nil {
				return
			}
		}
	}()

	// Read from UDP, write to stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 65535 {
				return
			}
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(n))
			if _, err := stream.Write(lenBuf); err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
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
			var err error
			c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				// try to set REUSEPORT, ignore error if not supported
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1); e != nil && err == nil {
					err = e
				}
			})
			return err
		},
	}
	return lc.Listen(nil, network, address)
}

func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1); e != nil && err == nil {
					err = e
				}
			})
			return err
		},
	}
	conn, err := lc.ListenPacket(nil, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
