package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

const (
	TCP_FORWARD  = 1
	UDP_FORWARD  = 2
	SO_REUSEPORT = 15 // Linux SO_REUSEPORT

	fakeSNI = "www.microsoft.com"

	// Timeouts
	tlsHandshakeTimeout = 10 * time.Second
	authTimeout         = 10 * time.Second
	udpSessionTimeout   = 2 * time.Minute
	udpCleanupInterval  = 30 * time.Second
	reconnectDelay      = 2 * time.Second

	// Padding limits
	minPaddingSize = 64
	maxPaddingSize = 256
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
	lastActive atomic.Int64 // Unix timestamp for lock-free access
	closed     atomic.Bool
}

func (u *UDPSession) updateLastActive() {
	u.lastActive.Store(time.Now().Unix())
}

func (u *UDPSession) isExpired(timeout time.Duration) bool {
	return time.Since(time.Unix(u.lastActive.Load(), 0)) > timeout
}

type RelayConnection struct {
	host      string
	conn      net.Conn
	session   *smux.Session
	active    atomic.Bool
	connected atomic.Bool
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

	serverTLSConfig *tls.Config
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
		serverTLSConfig = generateTLSConfig()
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

func generateTLSConfig() *tls.Config {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Microsoft Corporation"},
			CommonName:   fakeSNI,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{fakeSNI, "microsoft.com", "*.microsoft.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  privateKey,
		}},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}

func generateRandomPadding() ([]byte, error) {
	sizeBuf := make([]byte, 1)
	if _, err := rand.Read(sizeBuf); err != nil {
		return nil, err
	}
	size := minPaddingSize + int(sizeBuf[0])%(maxPaddingSize-minPaddingSize+1)
	padding := make([]byte, size)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return padding, nil
}

func sendPadding(conn net.Conn) error {
	padding, err := generateRandomPadding()
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(padding)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err = conn.Write(padding)
	return err
}

func receivePadding(conn net.Conn) error {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return err
	}
	length := binary.BigEndian.Uint16(lenBuf)
	if length > maxPaddingSize {
		return io.ErrUnexpectedEOF
	}
	padding := make([]byte, length)
	_, err := io.ReadFull(conn, padding)
	return err
}

// secureCompare performs constant-time comparison to prevent timing attacks
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func runRelay() {
	listener, err := createReusableListener("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay server listening on :%s (TLS enabled, SNI: %s)", *port, fakeSNI)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleRelayConnection(conn)
	}
}

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

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Set deadline for TLS handshake
	conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))

	tlsConn := tls.Server(conn, serverTLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer tlsConn.Close()

	// Set deadline for authentication phase
	tlsConn.SetDeadline(time.Now().Add(authTimeout))

	if err := receivePadding(tlsConn); err != nil {
		log.Printf("Failed to receive padding from %s: %v", conn.RemoteAddr(), err)
		return
	}

	tokLen := len(*token)
	tokBuf := make([]byte, tokLen)
	if _, err := io.ReadFull(tlsConn, tokBuf); err != nil {
		log.Printf("Auth read error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Constant-time comparison to prevent timing attacks
	if !secureCompare(tokBuf, []byte(*token)) {
		log.Printf("Authentication failed from %s", conn.RemoteAddr())
		return
	}

	closeCurrentSession()

	if err := sendPadding(tlsConn); err != nil {
		log.Printf("Failed to send padding to %s: %v", conn.RemoteAddr(), err)
		return
	}

	if _, err := tlsConn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		return
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)

	var forwardRules, forwardudpRules string
	if ruleLen > 0 {
		ruleBuf := make([]byte, ruleLen)
		if _, err := io.ReadFull(tlsConn, ruleBuf); err != nil {
			log.Printf("Failed to read forward rules: %v", err)
			return
		}

		parts := strings.Split(string(ruleBuf), "|")
		if len(parts) >= 1 {
			forwardRules = parts[0]
		}
		if len(parts) >= 2 {
			forwardudpRules = parts[1]
		}
	}
	log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)

	// Clear deadline for normal operation
	tlsConn.SetDeadline(time.Time{})

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(tlsConn, smuxConfig)
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	activeSession := setCurrentSession(session)

	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	for _, rule := range tcpRules {
		listener, err := createReusableListener("tcp", ":"+rule.srcPort)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
			continue
		}
		activeSession.addListener(listener)
		go startTCPForwarder(session, rule, listener)
	}

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
		go startUDPForwarder(session, rule, udpConn)
	}

	// Wait for session to close
	for !session.IsClosed() {
		time.Sleep(1 * time.Second)
	}
	log.Printf("Session closed")
}

func startTCPForwarder(session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()
	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !isClosedError(err) {
				log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
			}
			return
		}
		go handleTCPConnection(session, rule, conn)
	}
}

func handleTCPConnection(session *smux.Session, rule ForwardRule, conn net.Conn) {
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream for TCP forward: %v", err)
		return
	}
	defer stream.Close()

	// Send forward header
	portBytes := []byte(rule.targetPort)
	if len(portBytes) > 255 {
		log.Printf("Target port string too long: %s", rule.targetPort)
		return
	}
	header := make([]byte, 2+len(portBytes))
	header[0] = TCP_FORWARD
	header[1] = byte(len(portBytes))
	copy(header[2:], portBytes)

	if _, err := stream.Write(header); err != nil {
		log.Printf("Failed to write header to stream: %v", err)
		return
	}

	bidirectionalCopy(conn, stream)
}

func startUDPForwarder(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()
	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := &sync.Map{}

	// Cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ticker := time.NewTicker(udpCleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessions.Range(func(key, value interface{}) bool {
					sess := value.(*UDPSession)
					if sess.isExpired(udpSessionTimeout) {
						sess.closed.Store(true)
						sess.stream.Close()
						sessions.Delete(key)
					}
					return true
				})
			}
		}
	}()

	buf := make([]byte, 64*1024) // Max UDP size
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !isClosedError(err) {
				log.Printf("UDP read error on %s: %v", rule.srcPort, err)
			}
			// Cleanup all sessions
			sessions.Range(func(key, value interface{}) bool {
				sess := value.(*UDPSession)
				sess.closed.Store(true)
				sess.stream.Close()
				return true
			})
			return
		}

		sessionKey := clientAddr.String()

		sessVal, exists := sessions.Load(sessionKey)
		var sess *UDPSession

		if exists {
			sess = sessVal.(*UDPSession)
			if sess.closed.Load() {
				// Session was closed, remove and create new
				sessions.Delete(sessionKey)
				exists = false
			}
		}

		if !exists {
			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for UDP client %s: %v", sessionKey, err)
				continue
			}

			// Send forward header
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				log.Printf("Target port string too long: %s", rule.targetPort)
				stream.Close()
				continue
			}
			header := make([]byte, 2+len(portBytes))
			header[0] = UDP_FORWARD
			header[1] = byte(len(portBytes))
			copy(header[2:], portBytes)

			if _, err := stream.Write(header); err != nil {
				log.Printf("Failed to write UDP header: %v", err)
				stream.Close()
				continue
			}

			sess = &UDPSession{
				conn:       conn,
				stream:     stream,
				clientAddr: clientAddr,
			}
			sess.updateLastActive()

			sessions.Store(sessionKey, sess)

			// Start reader goroutine
			go udpStreamReader(sessions, sessionKey, sess)
		}

		sess.updateLastActive()

		// Send data with length prefix
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))

		if _, err := sess.stream.Write(lenBuf); err != nil {
			sess.closed.Store(true)
			sess.stream.Close()
			sessions.Delete(sessionKey)
			continue
		}
		if _, err := sess.stream.Write(buf[:n]); err != nil {
			sess.closed.Store(true)
			sess.stream.Close()
			sessions.Delete(sessionKey)
			continue
		}
	}
}

func udpStreamReader(sessions *sync.Map, sessionKey string, sess *UDPSession) {
	defer func() {
		sess.closed.Store(true)
		sess.stream.Close()
		sessions.Delete(sessionKey)
	}()

	buf := make([]byte, 64*1024)
	lenBuf := make([]byte, 2)

	for {
		if sess.closed.Load() {
			return
		}

		if _, err := io.ReadFull(sess.stream, lenBuf); err != nil {
			return
		}

		length := binary.BigEndian.Uint16(lenBuf)
		if int(length) > len(buf) {
			return
		}

		if _, err := io.ReadFull(sess.stream, buf[:length]); err != nil {
			return
		}

		if _, err := sess.conn.WriteToUDP(buf[:length], sess.clientAddr); err != nil {
			// Client might be gone, but don't close session yet
		}
		sess.updateLastActive()
	}
}

func runVPN() {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
	log.Printf("Strategy: %s", *strategy)
	log.Printf("TLS enabled with Chrome fingerprint, SNI: %s", fakeSNI)

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

func createUTLSConn(conn net.Conn, serverName string) (*utls.UConn, error) {
	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS13,
	}

	uconn := utls.UClient(conn, config, utls.HelloChrome_120)

	// Set deadline for handshake
	conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	return uconn, nil
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	for {
		log.Printf("[%s] Connecting to relay server...", relay.host)

		conn, err := net.DialTimeout("tcp", relay.host, 10*time.Second)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in %v...", relay.host, err, reconnectDelay)
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		tlsConn, err := createUTLSConn(conn, fakeSNI)
		if err != nil {
			log.Printf("[%s] TLS handshake failed: %v. Retrying in %v...", relay.host, err, reconnectDelay)
			conn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		// Set deadline for authentication
		tlsConn.SetDeadline(time.Now().Add(authTimeout))

		if err := sendPadding(tlsConn); err != nil {
			log.Printf("[%s] Failed to send padding: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		if _, err := tlsConn.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		if err := receivePadding(tlsConn); err != nil {
			log.Printf("[%s] Failed to receive padding: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Authentication failed or bad response: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		ruleLen := make([]byte, 2)
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := tlsConn.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send forward rules length: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := tlsConn.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send forward rules: %v", relay.host, err)
				tlsConn.Close()
				relay.connected.Store(false)
				time.Sleep(reconnectDelay)
				continue
			}
		}

		// Clear deadline for normal operation
		tlsConn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated (TLS with Chrome fingerprint)", relay.host)

		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second

		session, err := smux.Client(tlsConn, smuxConfig)
		if err != nil {
			log.Printf("[%s] Failed to create smux session: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(reconnectDelay)
			continue
		}

		relay.mu.Lock()
		relay.conn = tlsConn
		relay.session = session
		relay.mu.Unlock()
		relay.connected.Store(true)

		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		rm.handleVPNSession(relay, session)

		relay.connected.Store(false)
		relay.active.Store(false)

		session.Close()
		tlsConn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in %v...", relay.host, reconnectDelay)

		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		time.Sleep(reconnectDelay)
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
	return sess == nil || sess.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.strategy == "multi" {
		for _, relay := range rm.relays {
			isHealthy := relay.connected.Load() && !relay.sessionIsClosed()
			if isHealthy && !relay.active.Load() {
				relay.active.Store(true)
				log.Printf("[%s] Marked as ACTIVE (multi strategy)", relay.host)
			} else if !isHealthy && relay.active.Load() {
				relay.active.Store(false)
				log.Printf("[%s] Marked as INACTIVE (disconnected)", relay.host)
			}
		}
		return
	}

	// Failover strategy
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
		log.Printf("[%s] Marked as inactive", currentRelay.host)
	}

	for _, relay := range rm.relays {
		if relay.connected.Load() && !relay.sessionIsClosed() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}

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

			if proto == TCP_FORWARD {
				handleTCPStream(s, targetPort)
			} else if proto == UDP_FORWARD {
				handleUDPStream(s, targetPort)
			}
		}(stream)
	}
}

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

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> UDP
	go func() {
		defer wg.Done()
		defer cancel()

		buf := make([]byte, 64*1024)
		lenBuf := make([]byte, 2)

		for {
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

	// UDP -> Stream
	go func() {
		defer wg.Done()
		defer cancel()

		buf := make([]byte, 64*1024)
		lenBuf := make([]byte, 2)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

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

// bidirectionalCopy copies data between two connections with proper shutdown
func bidirectionalCopy(a, b net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		defer cancel()

		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				if _, err := dst.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}

	go copy(a, b)
	go copy(b, a)
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

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe")
}

func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return nil
		},
	}
	return lc.Listen(context.Background(), network, address)
}

func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, a string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
			return nil
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
