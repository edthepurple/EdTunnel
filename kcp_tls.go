package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
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
	transport     string // "tcp", "kcp"
	kcpKey        string
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
	transport  = flag.String("transport", "kcp", "Transport: tcp or kcp (default: kcp)")
	kcpKey     = flag.String("kcp-key", "", "KCP encryption key (default: derived from token)")

	// KCP tuning flags
	kcpMode   = flag.String("kcp-mode", "fast", "KCP mode: fast, normal, or conservative")
	kcpDS     = flag.Int("kcp-ds", 10, "KCP data shards for FEC (0 to disable)")
	kcpPS     = flag.Int("kcp-ps", 3, "KCP parity shards for FEC (0 to disable)")
	kcpMTU    = flag.Int("kcp-mtu", 1350, "KCP MTU size")
	kcpSndWnd = flag.Int("kcp-sndwnd", 1024, "KCP send window size")
	kcpRcvWnd = flag.Int("kcp-rcvwnd", 1024, "KCP receive window size")

	// TLS flags
	tlsEnabled = flag.Bool("tls", true, "Enable TLS encryption layer (default: true)")
	tlsCert    = flag.String("tls-cert", "", "Path to TLS certificate PEM file (auto-generated if empty)")
	tlsKey     = flag.String("tls-key", "", "Path to TLS private key PEM file (auto-generated if empty)")
	tlsPin     = flag.String("tls-pin", "", "Expected SHA-256 pin of relay's certificate (vpn mode, hex encoded)")
	tlsSave    = flag.String("tls-save", "", "Directory to save auto-generated cert/key for reuse")

	// Track current relay session for immediate cleanup on VPN reconnection
	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex

	// TLS server config (initialized at startup for relay mode)
	tlsServerConfig *tls.Config
)

// ──────────────────────────────────────────────────────────────────────────────
// KCP helpers
// ──────────────────────────────────────────────────────────────────────────────

// deriveKCPKey produces a 32-byte key from any passphrase via SHA-256.
func deriveKCPKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// newKCPBlock creates an AES-128 block cipher for KCP encryption.
// This encrypts the entire UDP payload making the traffic look like random
// bytes to DPI equipment.
func newKCPBlock(key []byte) (kcp.BlockCrypt, error) {
	// Use first 16 bytes for AES-128
	return kcp.NewAESBlockCrypt(key[:16])
}

// applyKCPMode configures KCP session parameters based on the selected mode.
func applyKCPMode(sess *kcp.UDPSession) {
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetMtu(*kcpMTU)
	sess.SetWindowSize(*kcpSndWnd, *kcpRcvWnd)
	sess.SetACKNoDelay(true)

	switch *kcpMode {
	case "fast":
		// NoDelay=1, interval=10ms, fast resend=2, no congestion control
		sess.SetNoDelay(1, 10, 2, 1)
	case "normal":
		// NoDelay=0, interval=30ms, fast resend=2, congestion control on
		sess.SetNoDelay(0, 30, 2, 1)
	case "conservative":
		// NoDelay=0, interval=40ms, no fast resend, congestion control on
		sess.SetNoDelay(0, 40, 0, 0)
	default:
		// Default to fast
		sess.SetNoDelay(1, 10, 2, 1)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS helpers
// ──────────────────────────────────────────────────────────────────────────────

// generateSelfSignedCert creates an ECDSA P-256 self-signed certificate valid
// for 10 years. Returns the tls.Certificate and the SHA-256 pin of the leaf.
func generateSelfSignedCert() (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "edtunnel"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"edtunnel"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parse key pair: %w", err)
	}

	pin := certPin(certDER)

	return tlsCert, pin, nil
}

// certPin returns the hex-encoded SHA-256 hash of a DER-encoded certificate.
func certPin(certDER []byte) string {
	h := sha256.Sum256(certDER)
	return hex.EncodeToString(h[:])
}

// saveCertAndKey writes PEM-encoded cert and key to the given directory.
func saveCertAndKey(dir string, cert tls.Certificate) error {
	certOut, err := os.Create(dir + "/edtunnel-cert.pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(dir+"/edtunnel-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return nil
}

// loadOrGenerateTLSConfig creates the relay server's TLS config.
// If cert/key paths are provided, it loads them; otherwise it auto-generates.
func loadOrGenerateTLSConfig() (*tls.Config, string, error) {
	var cert tls.Certificate
	var pin string
	var err error

	if *tlsCert != "" && *tlsKey != "" {
		cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return nil, "", fmt.Errorf("load cert/key: %w", err)
		}
		// Compute pin from the loaded certificate
		pin = certPin(cert.Certificate[0])
		log.Printf("Loaded TLS certificate from %s", *tlsCert)
	} else {
		cert, pin, err = generateSelfSignedCert()
		if err != nil {
			return nil, "", fmt.Errorf("generate cert: %w", err)
		}
		log.Printf("Generated self-signed TLS certificate")

		if *tlsSave != "" {
			if err := saveCertAndKey(*tlsSave, cert); err != nil {
				log.Printf("WARNING: Failed to save cert/key: %v", err)
			} else {
				log.Printf("Saved cert/key to %s/edtunnel-{cert,key}.pem", *tlsSave)
			}
		}
	}

	log.Printf("TLS certificate pin (SHA-256): %s", pin)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// Use only strong TLS 1.3 cipher suites (automatic with TLS 1.3)
	}

	return cfg, pin, nil
}

// newTLSClientConfig creates the VPN client's TLS config with optional pinning.
func newTLSClientConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Self-signed: skip CA verification
	}

	if *tlsPin != "" {
		expectedPin := strings.ToLower(strings.TrimSpace(*tlsPin))
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificates")
			}
			actualPin := certPin(cs.PeerCertificates[0].Raw)
			if actualPin != expectedPin {
				return fmt.Errorf("certificate pin mismatch: got %s, want %s", actualPin, expectedPin)
			}
			return nil
		}
	}

	return cfg
}

// wrapTLSServer wraps a net.Conn with server-side TLS.
func wrapTLSServer(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	tlsConn := tls.Server(conn, cfg)
	// Force handshake with timeout
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// wrapTLSClient wraps a net.Conn with client-side TLS.
func wrapTLSClient(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	tlsConn := tls.Client(conn, cfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	// Default KCP key to token if not specified
	if *kcpKey == "" {
		*kcpKey = *token
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

// ──────────────────────────────────────────────────────────────────────────────
// Relay server
// ──────────────────────────────────────────────────────────────────────────────

func runRelay() {
	// Initialize TLS if enabled
	if *tlsEnabled {
		cfg, pin, err := loadOrGenerateTLSConfig()
		if err != nil {
			log.Fatalf("TLS setup failed: %v", err)
		}
		tlsServerConfig = cfg
		_ = pin // Already logged in loadOrGenerateTLSConfig
	} else {
		log.Printf("WARNING: TLS disabled, tunnel traffic is not encrypted at the application layer")
	}

	switch *transport {
	case "kcp":
		runRelayKCP()
	case "tcp":
		runRelayTCP()
	default:
		log.Fatalf("Unknown transport: %s", *transport)
	}
}

func runRelayTCP() {
	listener, err := createReusableListener("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay server listening on TCP :%s (tls=%v)", *port, *tlsEnabled)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			if *tlsEnabled {
				tlsConn, err := wrapTLSServer(c, tlsServerConfig)
				if err != nil {
					log.Printf("TLS handshake failed from %s: %v", c.RemoteAddr(), err)
					c.Close()
					return
				}
				handleRelayConnection(tlsConn)
			} else {
				handleRelayConnection(c)
			}
		}(conn)
	}
}

func runRelayKCP() {
	key := deriveKCPKey(*kcpKey)
	block, err := newKCPBlock(key)
	if err != nil {
		log.Fatalf("Failed to create KCP block cipher: %v", err)
	}

	listener, err := kcp.ListenWithOptions(":"+*port, block, *kcpDS, *kcpPS)
	if err != nil {
		log.Fatalf("Failed to start KCP relay server: %v", err)
	}
	defer listener.Close()

	// Set listener-level socket buffer sizes
	listener.SetReadBuffer(4 * 1024 * 1024)
	listener.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("Relay server listening on KCP (UDP) :%s [mode=%s ds=%d ps=%d mtu=%d tls=%v]",
		*port, *kcpMode, *kcpDS, *kcpPS, *kcpMTU, *tlsEnabled)

	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			log.Printf("KCP accept error: %v", err)
			continue
		}

		applyKCPMode(conn)
		go func(c net.Conn) {
			if *tlsEnabled {
				tlsConn, err := wrapTLSServer(c, tlsServerConfig)
				if err != nil {
					log.Printf("TLS handshake failed from %s: %v", c.RemoteAddr(), err)
					c.Close()
					return
				}
				handleRelayConnection(tlsConn)
			} else {
				handleRelayConnection(c)
			}
		}(conn)
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

func handleRelayConnection(conn net.Conn) {
	defer conn.Close()

	// Disable Nagle's algorithm on TCP tunnel connections for lower latency
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

	// Create smux session with optimized config
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

	// Wait for all forwarder goroutines to finish
	forwarderWg.Wait()

	log.Printf("Session closed")
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
func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		closeOnDone.Close()
	}

	go copyDir(b, a, b) // a→b; on EOF close b
	go copyDir(a, b, a) // b→a; on EOF close a

	wg.Wait()
}

func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

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
			}(stream, sess, keyCopy)
		}

		sess.mu.Lock()
		if sess.closed {
			sess.mu.Unlock()
			continue
		}
		sess.lastActive = time.Now()

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

// ──────────────────────────────────────────────────────────────────────────────
// VPN client
// ──────────────────────────────────────────────────────────────────────────────

func runVPN() {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
	log.Printf("Strategy: %s, Transport: %s, TLS: %v", *strategy, *transport, *tlsEnabled)

	forwardRules := *forward + "|" + *forwardudp

	manager := &RelayManager{
		relays:        make([]*RelayConnection, len(hosts)),
		token:         *token,
		forwardRules:  forwardRules,
		strategy:      *strategy,
		transport:     *transport,
		kcpKey:        *kcpKey,
		reconnectChan: make(chan string, len(hosts)),
	}

	for i, h := range hosts {
		manager.relays[i] = &RelayConnection{
			host: h,
		}
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

// dialRelay connects to the relay using the configured transport (tcp or kcp),
// then optionally wraps the connection with TLS.
func (rm *RelayManager) dialRelay(host string) (net.Conn, error) {
	var conn net.Conn
	var err error

	switch rm.transport {
	case "kcp":
		key := deriveKCPKey(rm.kcpKey)
		block, err := newKCPBlock(key)
		if err != nil {
			return nil, err
		}
		sess, err := kcp.DialWithOptions(host, block, *kcpDS, *kcpPS)
		if err != nil {
			return nil, err
		}
		applyKCPMode(sess)
		conn = sess

	default: // "tcp"
		conn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
	}

	// Wrap with TLS if enabled
	if *tlsEnabled {
		tlsCfg := newTLSClientConfig()
		tlsConn, err := wrapTLSClient(conn, tlsCfg)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	for {
		log.Printf("[%s] Connecting via %s to relay server...", relay.host, rm.transport)

		conn, err := rm.dialRelay(relay.host)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in 2s...", relay.host, err)
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
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

		// Clear deadline after handshake
		conn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated via %s", relay.host, rm.transport)

		// Create smux session with optimized config
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

		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		rm.handleVPNSession(relay, session)

		relay.mu.Lock()
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		session.Close()
		conn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

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

	var wg sync.WaitGroup
	wg.Add(2)

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

// ──────────────────────────────────────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────────────────────────────────────

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

func createReusableListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
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
		Control: func(netw, a string, c syscall.RawConn) error {
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
