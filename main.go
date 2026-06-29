package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/smux"
)

const (
	TCP_FORWARD = 1
	UDP_FORWARD = 2

	// SO_REUSEPORT on Linux (x86/aarch64).
	SO_REUSEPORT = 15
)

// bufPool reuses 65549-byte slices for UDP frame construction (14-byte header + max UDP payload).
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65549)
		return &b
	},
}

// copyBufPool reuses 32 KiB buffers for bidirectionalCopy.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type ForwardRule struct {
	srcPort    string
	targetPort string
	proto      int // TCP_FORWARD or UDP_FORWARD
}

// RelayUDPSession tracks a public client's UDP session on the relay server.
type RelayUDPSession struct {
	clientAddr     *net.UDPAddr
	srcConn        *net.UDPConn
	lastActiveUnix int64 // Unix timestamp, accessed via sync/atomic
}

// VPNUDPSession tracks a local target connection on the VPN client.
type VPNUDPSession struct {
	conn           *net.UDPConn
	lastActiveUnix int64 // Unix timestamp, accessed via sync/atomic
	closed         bool
	mu             sync.Mutex
}

type RelayConnection struct {
	host      string
	conn      net.Conn
	session   *smux.Session
	active    atomic.Bool
	connected atomic.Bool
	mu        sync.Mutex

	udpTunnelConn *net.UDPConn
	udpSessions   map[uint32]*VPNUDPSession
	udpSessionsMu sync.Mutex
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

	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex

	tokenHash           uint64
	relayUDPTunnelConn  *net.UDPConn
	vpnEndpoint         atomic.Value // *net.UDPAddr
	relayUDPSessionsMu  sync.RWMutex
	relayUDPSessions    = make(map[string]uint32)
	relayUDPSessionsRev = make(map[uint32]*RelayUDPSession)
	relayNextSessionID  uint32 = 1
)

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	h := fnv.New64a()
	h.Write([]byte(*token))
	tokenHash = h.Sum64()

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("Port is required for relay mode")
		}
		runRelay()
	case "vpn":
		if *host == "" {
			log.Fatal("Host is required for vpn mode")
		}
		runVPN()
	default:
		log.Fatal("Invalid mode. Use 'relay' or 'vpn'")
	}
}

// ---------------------------------------------------------------------------
// Relay mode
// ---------------------------------------------------------------------------

func runRelay() {
	portInt, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}

	udpAddr := &net.UDPAddr{Port: portInt}
	relayUDPTunnelConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to start UDP tunnel listener: %v", err)
	}
	defer relayUDPTunnelConn.Close()

	log.Printf("Relay UDP tunnel listening on :%s", *port)
	// FIX: run handleRelayUDPTunnel in a restartable loop so that if the
	// tunnel conn ever errors (e.g. transient OS error), the goroutine
	// does not silently die and leave the relay deaf to VPN UDP traffic.
	go func() {
		for {
			handleRelayUDPTunnel(relayUDPTunnelConn)
			// relayUDPTunnelConn is a single long-lived socket; if
			// ReadFromUDP returns an error other than a deliberate close
			// we log and retry rather than exiting.
			log.Printf("handleRelayUDPTunnel exited — restarting loop")
			time.Sleep(100 * time.Millisecond)
		}
	}()
	go cleanStaleRelaySessions()

	listener, err := createReusableListener("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to start TCP relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay TCP server listening on :%s", *port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleRelayConnection(conn)
	}
}

func cleanStaleRelaySessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		nowUnix := time.Now().Unix()
		var staleIDs []uint32

		relayUDPSessionsMu.RLock()
		for id, sess := range relayUDPSessionsRev {
			if nowUnix-atomic.LoadInt64(&sess.lastActiveUnix) > 120 {
				staleIDs = append(staleIDs, id)
			}
		}
		relayUDPSessionsMu.RUnlock()

		if len(staleIDs) > 0 {
			relayUDPSessionsMu.Lock()
			for _, id := range staleIDs {
				sess, exists := relayUDPSessionsRev[id]
				if exists && nowUnix-atomic.LoadInt64(&sess.lastActiveUnix) > 120 {
					delete(relayUDPSessions, sess.clientAddr.String())
					delete(relayUDPSessionsRev, id)
				}
			}
			relayUDPSessionsMu.Unlock()
		}
	}
}

func handleRelayUDPTunnel(conn *net.UDPConn) {
	buf := make([]byte, 65549)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 14 {
			continue
		}

		if binary.BigEndian.Uint64(buf[0:8]) != tokenHash {
			continue
		}

		sessionID := binary.BigEndian.Uint32(buf[8:12])

		if sessionID == 0 {
			vpnEndpoint.Store(addr)
			continue
		}

		relayUDPSessionsMu.RLock()
		sess, ok := relayUDPSessionsRev[sessionID]
		if ok {
			atomic.StoreInt64(&sess.lastActiveUnix, time.Now().Unix())
		}
		relayUDPSessionsMu.RUnlock()

		if ok {
			if _, err := sess.srcConn.WriteToUDP(buf[14:n], sess.clientAddr); err != nil {
				log.Printf("relay UDP write to client %s: %v", sess.clientAddr, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Relay connection handling
// ---------------------------------------------------------------------------

func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	if currentRelaySession == nil {
		return
	}

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

	// FIX: flush stale UDP session maps so the new listener conn is used.
	// Without this, relayUDPSessionsRev still holds entries pointing at the
	// now-closed srcConn from the old session, causing "use of closed network
	// connection" errors on every UDP packet until the 120-second stale
	// eviction fires — and never firing at all if keepalives keep sessions
	// fresh.
	relayUDPSessionsMu.Lock()
	relayUDPSessions = make(map[string]uint32)
	relayUDPSessionsRev = make(map[uint32]*RelayUDPSession)
	atomic.StoreUint32(&relayNextSessionID, 1)
	relayUDPSessionsMu.Unlock()
	log.Printf("UDP session maps flushed")
}

func setCurrentSession(session *smux.Session) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()
	currentRelaySession = &ActiveRelaySession{
		session:   session,
		listeners: make([]io.Closer, 0),
	}
	return currentRelaySession
}

func (ars *ActiveRelaySession) addListener(l io.Closer) {
	ars.mu.Lock()
	defer ars.mu.Unlock()
	ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(conn net.Conn) {
	defer conn.Close()
	setTCPNoDelay(conn)

	if !authenticateRelayClient(conn) {
		return
	}

	forwardRules, forwardudpRules, ok := receiveForwardRules(conn)
	if !ok {
		return
	}
	log.Printf("Received forward rules — TCP: %q  UDP: %q", forwardRules, forwardudpRules)

	session, err := newSmuxServer(conn)
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	activeSession := setCurrentSession(session)
	launchRelayForwarders(session, activeSession, forwardRules, forwardudpRules)

	for !session.IsClosed() {
		time.Sleep(time.Second)
	}
	log.Printf("Session closed")
}

func authenticateRelayClient(conn net.Conn) bool {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	tokBuf := make([]byte, len(*token))
	if _, err := io.ReadFull(conn, tokBuf); err != nil {
		return false
	}
	if string(tokBuf) != *token {
		log.Printf("Authentication failed from %s", conn.RemoteAddr())
		return false
	}

	closeCurrentSession()

	if _, err := conn.Write([]byte("OK")); err != nil {
		return false
	}
	log.Printf("VPN client authenticated: %s", conn.RemoteAddr())
	return true
}

func receiveForwardRules(conn net.Conn) (tcpRules, udpRules string, ok bool) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", "", false
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)
	if ruleLen == 0 {
		return "", "", false
	}
	ruleBuf := make([]byte, ruleLen)
	if _, err := io.ReadFull(conn, ruleBuf); err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(ruleBuf), "|", 2)
	if len(parts) >= 1 {
		tcpRules = parts[0]
	}
	if len(parts) >= 2 {
		udpRules = parts[1]
	}
	return tcpRules, udpRules, true
}

func launchRelayForwarders(session *smux.Session, activeSession *ActiveRelaySession, forwardRules, forwardudpRules string) {
	for _, rule := range parseForwardRules(forwardRules, TCP_FORWARD) {
		listener, err := createReusableListener("tcp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(listener)
		go startTCPForwarderWithListener(session, rule, listener)
	}

	for _, rule := range parseForwardRules(forwardudpRules, UDP_FORWARD) {
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
		go startUDPForwarderWithConn(rule, udpConn)
	}
}

func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()
	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !session.IsClosed() {
				log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
			}
			return
		}
		go relayTCPConn(conn, session, rule.targetPort)
	}
}

func relayTCPConn(conn net.Conn, session *smux.Session, targetPort string) {
	defer conn.Close()
	setTCPNoDelay(conn)

	stream, err := session.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	header := buildTCPStreamHeader(targetPort)
	if _, err := stream.Write(header); err != nil {
		return
	}

	bidirectionalCopy(conn, stream)
}

func buildTCPStreamHeader(targetPort string) []byte {
	portBytes := []byte(targetPort)
	hdr := make([]byte, 2+len(portBytes))
	hdr[0] = TCP_FORWARD
	hdr[1] = byte(len(portBytes))
	copy(hdr[2:], portBytes)
	return hdr
}

func startUDPForwarderWithConn(rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()
	log.Printf("Forwarding UDP %s -> %s (RAW tunnel)", rule.srcPort, rule.targetPort)

	targetPortInt, err := strconv.Atoi(rule.targetPort)
	if err != nil {
		log.Printf("UDP forwarder: invalid target port %q: %v", rule.targetPort, err)
		return
	}
	targetPort16 := uint16(targetPortInt)

	for {
		framep := bufPool.Get().(*[]byte)

		// Optimization: Zero-Copy read ingestion straight into the pooled frame slice
		n, clientAddr, err := conn.ReadFromUDP((*framep)[14:])
		if err != nil {
			bufPool.Put(framep)
			break
		}

		addrStr := clientAddr.String()
		var sessionID uint32
		nowUnix := time.Now().Unix()

		// Optimization: Read Lock fast path avoids global write contention
		relayUDPSessionsMu.RLock()
		sess, exists := relayUDPSessions[addrStr]
		if exists {
			sessionID = sess
			atomic.StoreInt64(&relayUDPSessionsRev[sessionID].lastActiveUnix, nowUnix)
			relayUDPSessionsMu.RUnlock()
		} else {
			relayUDPSessionsMu.RUnlock()

			// Slow Path: Write lock only when mapping a new client socket session
			relayUDPSessionsMu.Lock()
			sessionID, exists = relayUDPSessions[addrStr]
			if !exists {
				sessionID = atomic.AddUint32(&relayNextSessionID, 1)
				relayUDPSessions[addrStr] = sessionID
				relayUDPSessionsRev[sessionID] = &RelayUDPSession{
					clientAddr:     clientAddr,
					srcConn:        conn,
					lastActiveUnix: nowUnix,
				}
			} else {
				atomic.StoreInt64(&relayUDPSessionsRev[sessionID].lastActiveUnix, nowUnix)
			}
			relayUDPSessionsMu.Unlock()
		}

		ep := vpnEndpoint.Load()
		if ep == nil {
			bufPool.Put(framep)
			continue
		}
		vpnAddr := ep.(*net.UDPAddr)

		frame := (*framep)[:14+n]
		binary.BigEndian.PutUint64(frame[0:8], tokenHash)
		binary.BigEndian.PutUint32(frame[8:12], sessionID)
		binary.BigEndian.PutUint16(frame[12:14], targetPort16)

		if _, err := relayUDPTunnelConn.WriteToUDP(frame, vpnAddr); err != nil {
			log.Printf("relay UDP tunnel write: %v", err)
		}
		bufPool.Put(framep)
	}
}

// ---------------------------------------------------------------------------
// VPN mode
// ---------------------------------------------------------------------------

func runVPN() {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy %q. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay server(s): %v", len(hosts), hosts)
	log.Printf("Strategy: %s", *strategy)

	forwardRules := buildForwardRuleString(*forward, *forwardudp)

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

	var wg sync.WaitGroup
	for _, relay := range manager.relays {
		wg.Add(1)
		go func(r *RelayConnection) {
			defer wg.Done()
			manager.maintainConnection(r)
		}(relay)
	}

	go manager.monitorRelays()
	wg.Wait()
}

func buildForwardRuleString(tcp, udp string) string {
	if udp == "" {
		return tcp
	}
	return tcp + "|" + udp
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	for {
		if err := rm.connectOnce(relay); err != nil {
			log.Printf("[%s] Connection failed: %v. Retrying in 2s...", relay.host, err)
		}
		time.Sleep(2 * time.Second)
	}
}

func (rm *RelayManager) connectOnce(relay *RelayConnection) error {
	conn, err := net.DialTimeout("tcp", relay.host, 10*time.Second)
	if err != nil {
		relay.connected.Store(false)
		return err
	}
	setTCPNoDelay(conn)

	if err := rm.handshake(conn); err != nil {
		conn.Close()
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", relay.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("resolve UDP host: %w", err)
	}
	udpTunnelConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("UDP tunnel dial: %w", err)
	}

	relay.mu.Lock()
	relay.udpTunnelConn = udpTunnelConn
	relay.udpSessions = make(map[uint32]*VPNUDPSession)
	relay.mu.Unlock()

	stopTunnel := make(chan struct{})

	go rm.runKeepalive(udpTunnelConn, stopTunnel)
	go rm.handleVPNUDPTunnel(relay, udpTunnelConn)
	go rm.cleanStaleVPNSessions(relay, stopTunnel)

	log.Printf("[%s] Connected and authenticated (TCP + UDP)", relay.host)

	session, err := smux.Client(conn, newSmuxConfig())
	if err != nil {
		close(stopTunnel)
		udpTunnelConn.Close()
		conn.Close()
		return fmt.Errorf("smux client: %w", err)
	}

	relay.mu.Lock()
	relay.conn = conn
	relay.session = session
	relay.connected.Store(true)
	relay.mu.Unlock()

	select {
	case rm.reconnectChan <- relay.host:
	default:
	}

	rm.handleVPNSession(relay, session)

	close(stopTunnel)
	udpTunnelConn.Close()

	relay.mu.Lock()
	relay.active.Store(false)
	relay.connected.Store(false)
	relay.session = nil
	relay.conn = nil
	for _, sess := range relay.udpSessions {
		sess.mu.Lock()
		if !sess.closed {
			sess.closed = true
			sess.conn.Close()
		}
		sess.mu.Unlock()
	}
	relay.udpSessions = nil
	relay.mu.Unlock()

	session.Close()
	conn.Close()
	log.Printf("[%s] Connection lost", relay.host)

	select {
	case rm.reconnectChan <- relay.host:
	default:
	}

	return nil
}

func (rm *RelayManager) handshake(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte(rm.token)); err != nil {
		return fmt.Errorf("send token: %w", err)
	}

	okBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
		return fmt.Errorf("auth rejected")
	}

	ruleLen := make([]byte, 2)
	binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
	if _, err := conn.Write(ruleLen); err != nil {
		return fmt.Errorf("send rule length: %w", err)
	}
	if len(rm.forwardRules) > 0 {
		if _, err := conn.Write([]byte(rm.forwardRules)); err != nil {
			return fmt.Errorf("send rules: %w", err)
		}
	}
	return nil
}

func (rm *RelayManager) runKeepalive(conn *net.UDPConn, stop <-chan struct{}) {
	kaFrame := make([]byte, 14)
	binary.BigEndian.PutUint64(kaFrame[0:8], tokenHash)

	if _, err := conn.Write(kaFrame); err != nil {
		log.Printf("UDP keepalive initial write: %v", err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := conn.Write(kaFrame); err != nil {
				log.Printf("UDP keepalive write: %v", err)
			}
		case <-stop:
			return
		}
	}
}

func (rm *RelayManager) cleanStaleVPNSessions(relay *RelayConnection, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			nowUnix := time.Now().Unix()
			var staleIDs []uint32

			// Optimization: Gather targets without stalling tunnel routing map lookups
			relay.udpSessionsMu.Lock()
			for id, sess := range relay.udpSessions {
				if nowUnix-atomic.LoadInt64(&sess.lastActiveUnix) > 120 {
					sess.mu.Lock()
					if !sess.closed {
						sess.closed = true
						sess.conn.Close()
					}
					sess.mu.Unlock()
					staleIDs = append(staleIDs, id)
				}
			}
			for _, id := range staleIDs {
				delete(relay.udpSessions, id)
			}
			relay.udpSessionsMu.Unlock()
		case <-stop:
			return
		}
	}
}

func (rm *RelayManager) handleVPNUDPTunnel(relay *RelayConnection, tunnelConn *net.UDPConn) {
	defer tunnelConn.Close()

	buf := make([]byte, 65549)
	for {
		n, err := tunnelConn.Read(buf)
		if err != nil {
			return
		}
		if n < 14 {
			continue
		}
		if binary.BigEndian.Uint64(buf[0:8]) != tokenHash {
			continue
		}

		sessionID := binary.BigEndian.Uint32(buf[8:12])
		targetPort := binary.BigEndian.Uint16(buf[12:14])

		if sessionID == 0 {
			continue
		}
		if !relay.active.Load() {
			continue
		}

		relay.udpSessionsMu.Lock()
		sess, exists := relay.udpSessions[sessionID]
		if !exists {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", targetPort))
			if err != nil {
				relay.udpSessionsMu.Unlock()
				continue
			}
			localConn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				relay.udpSessionsMu.Unlock()
				continue
			}

			sess = &VPNUDPSession{
				conn:           localConn,
				lastActiveUnix: time.Now().Unix(),
			}
			relay.udpSessions[sessionID] = sess
			go rm.handleVPNUDPLocal(relay, tunnelConn, sessionID, targetPort, sess)
		}
		relay.udpSessionsMu.Unlock()

		sess.mu.Lock()
		if !sess.closed {
			atomic.StoreInt64(&sess.lastActiveUnix, time.Now().Unix())
			if _, err := sess.conn.Write(buf[14:n]); err != nil {
				log.Printf("VPN UDP local write (session %d): %v", sessionID, err)
			}
		}
		sess.mu.Unlock()
	}
}

func (rm *RelayManager) handleVPNUDPLocal(relay *RelayConnection, tunnelConn *net.UDPConn, sessionID uint32, targetPort uint16, sess *VPNUDPSession) {
	defer func() {
		relay.udpSessionsMu.Lock()
		if v, ok := relay.udpSessions[sessionID]; ok && v == sess {
			delete(relay.udpSessions, sessionID)
		}
		relay.udpSessionsMu.Unlock()

		sess.mu.Lock()
		if !sess.closed {
			sess.closed = true
			sess.conn.Close()
		}
		sess.mu.Unlock()
	}()

	for {
		framep := bufPool.Get().(*[]byte)
		sess.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))

		// Optimization: Zero-Copy read ingestion straight into the pooled frame slice
		n, err := sess.conn.Read((*framep)[14:])
		if err != nil {
			bufPool.Put(framep)
			return
		}

		atomic.StoreInt64(&sess.lastActiveUnix, time.Now().Unix())

		frame := (*framep)[:14+n]
		binary.BigEndian.PutUint64(frame[0:8], tokenHash)
		binary.BigEndian.PutUint32(frame[8:12], sessionID)
		binary.BigEndian.PutUint16(frame[12:14], targetPort)

		if _, err := tunnelConn.Write(frame); err != nil {
			log.Printf("VPN UDP tunnel write (session %d): %v", sessionID, err)
			bufPool.Put(framep)
			return
		}
		bufPool.Put(framep)
	}
}

// ---------------------------------------------------------------------------
// Relay monitor
// ---------------------------------------------------------------------------

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
	defer r.mu.Unlock()
	return r.session == nil || r.session.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		for _, relay := range rm.relays {
			wasActive := relay.active.Load()
			shouldBeActive := relay.connected.Load() && !relay.sessionIsClosed()
			if shouldBeActive && !wasActive {
				relay.active.Store(true)
				log.Printf("[%s] Marked ACTIVE (multi)", relay.host)
			} else if !shouldBeActive && wasActive {
				relay.active.Store(false)
				log.Printf("[%s] Marked INACTIVE (disconnected)", relay.host)
			}
		}
		return
	}

	currentActive := rm.activeRelay.Load()
	var currentRelay *RelayConnection
	if currentActive != nil {
		currentRelay = currentActive.(*RelayConnection)
	}
	if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.sessionIsClosed() {
		return
	}

	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked inactive (failover)", currentRelay.host)
	}

	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.sessionIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE (failover)", relay.host)
			return
		}
	}
	log.Printf("WARNING: no relay servers available, waiting for reconnection...")
}

// ---------------------------------------------------------------------------
// VPN TCP stream handling
// ---------------------------------------------------------------------------

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
			rm.dispatchStream(relay, s)
		}(stream)
	}
	streamWg.Wait()
}

func (rm *RelayManager) dispatchStream(relay *RelayConnection, s *smux.Stream) {
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

	if !relay.active.Load() {
		return
	}

	switch proto {
	case TCP_FORWARD:
		handleTCPStream(s, targetPort)
	default:
		log.Printf("dispatchStream: unknown proto byte %d for port %s — dropping stream", proto, targetPort)
	}
}

func handleTCPStream(stream *smux.Stream, targetPort string) {
	target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to local target %s: %v", targetPort, err)
		return
	}
	defer target.Close()
	setTCPNoDelay(target)
	bidirectionalCopy(stream, target)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer) {
		defer wg.Done()
		bufp := copyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(dst, src, *bufp)
		copyBufPool.Put(bufp)
		closeOnDone.Close()
	}
	go copyDir(b, a, b)
	go copyDir(a, b, a)
	wg.Wait()
}

func setTCPNoDelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
}

func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024 // Optimized for high throughput BDP scaling
	cfg.MaxStreamBuffer = 4 * 1024 * 1024
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

func newSmuxServer(conn net.Conn) (*smux.Session, error) {
	return smux.Server(conn, newSmuxConfig())
}

func parseForwardRules(rules string, proto int) []ForwardRule {
	if rules == "" {
		return nil
	}
	var result []ForwardRule
	for _, pair := range strings.Split(rules, ";") {
		parts := strings.SplitN(pair, ",", 2)
		if len(parts) != 2 {
			log.Printf("parseForwardRules: skipping malformed pair %q (no comma)", pair)
			continue
		}
		src := strings.TrimSpace(parts[0])
		tgt := strings.TrimSpace(parts[1])
		if src == "" || tgt == "" {
			log.Printf("parseForwardRules: skipping pair %q (empty src or target)", pair)
			continue
		}
		result = append(result, ForwardRule{srcPort: src, targetPort: tgt, proto: proto})
	}
	return result
}

func createReusableListener(network, address string) (net.Listener, error) {
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
	return lc.Listen(nil, network, address)
}

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
	conn, err := lc.ListenPacket(nil, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
