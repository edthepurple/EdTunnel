package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/smux"
)

func init() {
	// Use all CPUs – this gives the best possible CPU utilisation
	runtime.GOMAXPROCS(runtime.NumCPU())
}

const (
	TCP_FORWARD  = 1
	UDP_FORWARD  = 2
	SO_REUSEPORT = 15 // Linux SO_REUSEPORT
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
	closed     bool // guarded by mu; prevents double‑close
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

	// Buffer pools – minimise GC pressure for the hot data paths
	tcpCopyBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024) // 32 KB per direction
			return b
		},
	}
	udpFramePool = sync.Pool{
		// 2‑byte length prefix + max UDP payload (65535)
		New: func() interface{} {
			b := make([]byte, 65535+2)
			return b
		},
	}
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

/* ====================== RELAY (SERVER) ====================== */

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

// closeCurrentSession closes the previous session and all its listeners.
// It is called *before* the new tunnel authenticates, guaranteeing
// that ports are freed immediately for the reconnecting client.
func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	if currentRelaySession != nil {
		currentRelaySession.mu.Lock()
		log.Printf("Closing previous session to allow immediate reconnection...")

		for _, l := range currentRelaySession.listeners {
			l.Close()
		}
		currentRelaySession.listeners = nil

		if currentRelaySession.session != nil && !currentRelaySession.session.IsClosed() {
			currentRelaySession.session.Close()
		}
		currentRelaySession.mu.Unlock()
		currentRelaySession = nil
		log.Printf("Previous session closed, ports freed")
	}
}

// setCurrentSession registers the new active session and returns the wrapper.
func setCurrentSession(session *smux.Session) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	currentRelaySession = &ActiveRelaySession{
		session:   session,
		listeners: make([]io.Closer, 0),
	}
	return currentRelaySession
}

// addListener registers a listener (TCP or UDP) belonging to the current session.
func (ars *ActiveRelaySession) addListener(l io.Closer) {
	ars.mu.Lock()
	ars.listeners = append(ars.listeners, l)
	ars.mu.Unlock()
}

func handleRelayConnection(conn net.Conn) {
	defer conn.Close()

	// Disable Nagle on the tunnel of the relay → VPN direction
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// ---- authentication -------------------------------------------------
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

	// Close any existing session *before* we answer, guaranteeing immediate port reuse.
	closeCurrentSession()

	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

	// ---- receive forward rules -----------------------------------------
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
	parts := strings.Split(string(ruleBuf), "|")
	var forwardRules, forwardudpRules string
	if len(parts) >= 1 {
		forwardRules = parts[0]
	}
	if len(parts) >= 2 {
		forwardudpRules = parts[1]
	}
	log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)

	// ---- smux session -------------------------------------------------
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // 4 MiB
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024  // 1 MiB
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	activeSession := setCurrentSession(session)

	// ---- parse rules --------------------------------------------------
	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	var forwarderWg sync.WaitGroup

	// ---- start TCP forwarders -----------------------------------------
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

	// ---- start UDP forwarders -----------------------------------------
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

	// ---- keep the session alive ---------------------------------------
	for !session.IsClosed() {
		time.Sleep(time.Second)
	}

	// ---- shutdown ------------------------------------------------------
	forwarderWg.Wait()
	log.Printf("Session closed")
}

/* -------------------------- TCP FORWARDER -------------------------- */

func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	// pre‑built header – reused for every inbound connection
	forwardHeader := []byte{TCP_FORWARD, byte(len(rule.targetPort))}
	forwardHeader = append(forwardHeader, []byte(rule.targetPort)...)

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !session.IsClosed() {
				log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
			}
			return
		}

		go func(c net.Conn) {
			defer c.Close()

			if tcpConn, ok := c.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}

			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for TCP forward: %v", err)
				return
			}
			defer stream.Close()

			if _, err := stream.Write(forwardHeader); err != nil {
				log.Printf("Failed to write header to stream: %v", err)
				return
			}
			bidirectionalCopy(c, stream)
		}(conn)
	}
}

/* -------------------------- UDP FORWARDER -------------------------- */

func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := make(map[string]*UDPSession) // client address → session
	var sessionsMu sync.Mutex

	// --------------------------------------------------------------
	// Cleanup goroutine – removes idle client sessions.
	stopCleanup := make(chan struct{})
	var cleanupWg sync.WaitGroup
	cleanupWg.Add(1)
	go func() {
		defer cleanupWg.Done()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stopCleanup:
				return
			case <-tick.C:
				sessionsMu.Lock()
				now := time.Now()
				for key, s := range sessions {
					s.mu.Lock()
					if now.Sub(s.lastActive) > 2*time.Minute && !s.closed {
						s.closed = true
						s.stream.Close()
						delete(sessions, key)
					}
					s.mu.Unlock()
				}
				sessionsMu.Unlock()
			}
		}
	}()

	// --------------------------------------------------------------
	// Main UDP receive loop – reads from the local socket and forwards
	// data to the correct client‑specific smux stream.
	buf := make([]byte, 65535) // receive buffer
	for {
		// Abort early if the tunnel is gone – this frees the UDP port instantly.
		if session.IsClosed() {
			break
		}

		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		sessionKey := clientAddr.String()

		// ---------------------------------------------------------- get / create per‑client session
		sessionsMu.Lock()
		sess, ok := sessions[sessionKey]
		sessionsMu.Unlock()

		if !ok {
			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for UDP client %s: %v", sessionKey, err)
				continue
			}
			// send per‑client UDP header
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

			// ------------------------------------------------------ read‑loop for responses
			go func(s *smux.Stream, udpSess *UDPSession, key string) {
				defer func() {
					sessionsMu.Lock()
					if v, ok := sessions[key]; ok && v == udpSess {
						delete(sessions, key)
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
					if _, err := io.ReadFull(s, lenBuf); err != nil {
						return
					}
					length := binary.BigEndian.Uint16(lenBuf)
					if int(length) > len(respBuf) {
						return
					}
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
			}(stream, sess, sessionKey)
		}

		// ---------------------------------------------------------- write packet to stream
		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			// session already closed – let cleanup goroutine reclaim it
			continue
		}
		sess.lastActive = time.Now()
		stream := sess.stream
		sess.mu.Unlock()

		// Build length‑prefixed frame using the pool
		frame := udpFramePool.Get().([]byte)
		if cap(frame) < n+2 {
			// very unlikely, but handle it safely
			frame = make([]byte, n+2)
		}
		frame = frame[:n+2]
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])

		if _, err := stream.Write(frame); err != nil {
			// return buffer to pool if possible
			if cap(frame) == 65535+2 {
				udpFramePool.Put(frame[:cap(frame)])
			}
			// Mark the per‑client session as dead
			sess.mu.Lock()
			if !sess.closed {
				sess.closed = true
				stream.Close()
			}
			sess.mu.Unlock()

			sessionsMu.Lock()
			if v, ok := sessions[sessionKey]; ok && v == sess {
				delete(sessions, sessionKey)
			}
			sessionsMu.Unlock()
			continue
		}
		// Return frame to pool for reuse
		if cap(frame) == 65535+2 {
			udpFramePool.Put(frame[:cap(frame)])
		}
	}

	// -------------------------------------------------------------- cleanup
	close(stopCleanup)
	cleanupWg.Wait()

	sessionsMu.Lock()
	for key, s := range sessions {
		s.mu.Lock()
		if !s.closed {
			s.closed = true
			s.stream.Close()
		}
		s.mu.Unlock()
		delete(sessions, key)
	}
	sessionsMu.Unlock()

	log.Printf("UDP forwarder %s stopped", rule.srcPort)
}

/* -------------------------- VPN (CLIENT) -------------------------- */

func runVPN() {
	// Validate strategy
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

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

	for i, h := range hosts {
		manager.relays[i] = &RelayConnection{host: h}
	}

	// start a connection manager for every configured relay
	var wg sync.WaitGroup
	for _, r := range manager.relays {
		wg.Add(1)
		go func(rel *RelayConnection) {
			defer wg.Done()
			manager.maintainConnection(rel)
		}(r)
	}
	go manager.monitorRelays()
	wg.Wait()
}

/* ---------------------- CONNECTION MANAGER ---------------------- */

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
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		// ---- auth ----------------------------------------------------
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

		// ---- forward‑rules -------------------------------------------
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(rm.forwardRules)))
		if _, err := conn.Write(lenBuf); err != nil {
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
		conn.SetDeadline(time.Time{}) // clear deadline
		log.Printf("[%s] Connected and authenticated", relay.host)

		// ---- smux ----------------------------------------------------
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
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

		relay.mu.Lock()
		relay.conn = conn
		relay.session = session
		relay.lastCheck = time.Now()
		relay.connected.Store(true)
		relay.mu.Unlock()

		// signal availability
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		// block while the VPN tunnel is up
		rm.handleVPNSession(relay, session)

		// ----- cleanup after the tunnel goes down -----
		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		session.Close()
		conn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

		// let the monitor know something changed
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}
		time.Sleep(2 * time.Second)
	}
}

// monitorRelays watches the health of all relays and enforces the chosen strategy.
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

// sessionIsClosed safely checks whether a relay's smux session has been closed.
func (r *RelayConnection) sessionIsClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session == nil {
		return true
	}
	return r.session.IsClosed()
}

// checkAndSwitchRelay activates/deactivates relays based on the chosen strategy.
func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		// every healthy relay stays active
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

	// ---------- failover ----------
	currentActive := rm.activeRelay.Load()
	var currentRelay *RelayConnection
	if currentActive != nil {
		currentRelay = currentActive.(*RelayConnection)
	}
	if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.sessionIsClosed() {
		// the currently‑active relay is still healthy
		return
	}
	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked as INACTIVE (failover)", currentRelay.host)
	}
	// pick the first healthy relay
	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.sessionIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}
	// no relay reachable at the moment
	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available, waiting for reconnection...")
	}
}

// handleVPNSession processes incoming streams from the relay server.
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

			// In failover mode we ignore traffic on non‑active relays.
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
	streamWg.Wait()
}

/* -------------------------- TCP HANDLER -------------------------- */

func handleTCPStream(stream *smux.Stream, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	bidirectionalCopy(stream, target)
}

/* -------------------------- UDP HANDLER -------------------------- */

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

	// stream → UDP
	go func() {
		defer wg.Done()
		lenBuf := make([]byte, 2)
		tmp := make([]byte, 65535)
		for {
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				stream.Close()
				return
			}
			n := binary.BigEndian.Uint16(lenBuf)
			if int(n) > len(tmp) {
				stream.Close()
				return
			}
			if _, err := io.ReadFull(stream, tmp[:n]); err != nil {
				stream.Close()
				return
			}
			if _, err := conn.Write(tmp[:n]); err != nil {
				return
			}
		}
	}()

	// UDP → stream
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
			frame := udpFramePool.Get().([]byte)
			if cap(frame) < n+2 {
				frame = make([]byte, n+2)
			}
			frame = frame[:n+2]
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			copy(frame[2:], buf[:n])
			if _, err := stream.Write(frame); err != nil {
				if cap(frame) == 65535+2 {
					udpFramePool.Put(frame[:cap(frame)])
				}
				stream.Close()
				return
			}
			if cap(frame) == 65535+2 {
				udpFramePool.Put(frame[:cap(frame)])
			}
		}
	}()

	wg.Wait()
}

/* ------------------------- UTILITIES -------------------------- */

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
			if src != "" && tgt != "" {
				result = append(result, ForwardRule{
					srcPort:    src,
					targetPort: tgt,
					proto:      proto,
				})
			}
		}
	}
	return result
}

// createReusableListener creates a TCP listener with SO_REUSEADDR.
// SO_REUSEPORT is attempted but ignored if unsupported.
func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
				// best‑effort: ignore errors on REUSEPORT (not available everywhere)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return setErr
		},
	}
	return lc.Listen(nil, network, address)
}

// createReusableUDPListener creates a UDP socket with SO_REUSEADDR.
// SO_REUSEPORT is attempted on a best‑effort basis.
func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var setErr error
			c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					setErr = err
				}
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

// bidirectionalCopy copies data in both directions using a reusable buffer pool.
// It closes each side when the opposite direction hits EOF or an error,
// ensuring no goroutine leaks.
func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// a → b
	go func() {
		defer wg.Done()
		buf := tcpCopyBufferPool.Get().([]byte)
		defer tcpCopyBufferPool.Put(buf)
		_, _ = io.CopyBuffer(b, a, buf)
		// close the opposite direction to unblock it
		b.Close()
	}()

	// b → a
	go func() {
		defer wg.Done()
		buf := tcpCopyBufferPool.Get().([]byte)
		defer tcpCopyBufferPool.Put(buf)
		_, _ = io.CopyBuffer(a, b, buf)
		a.Close()
	}()

	wg.Wait()
}
