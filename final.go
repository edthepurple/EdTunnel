package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"math/big"
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
	SO_REUSEPORT = 15
)

// Buffer pool for reducing GC pressure
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 16*1024)
		return &buf
	},
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

type ForwardRule struct {
	srcPort    string
	targetPort string
	proto      int
}

type UDPSession struct {
	conn       *net.UDPConn
	stream     *smux.Stream
	clientAddr *net.UDPAddr
	lastActive atomic.Int64
	closed     atomic.Bool
	batcher    *UDPBatcher
}

type UDPBatcher struct {
	stream      *smux.Stream
	mu          sync.Mutex
	buffer      []byte
	packetCount int
	maxSize     int
	maxPackets  int
	flushTimer  *time.Timer
	flushDelay  time.Duration
	closed      atomic.Bool
}

func NewUDPBatcher(stream *smux.Stream) *UDPBatcher {
	b := &UDPBatcher{
		stream:     stream,
		buffer:     make([]byte, 0, 32*1024),
		maxSize:    32 * 1024,
		maxPackets: 16,
		flushDelay: 1 * time.Millisecond,
	}
	return b
}

func (b *UDPBatcher) Write(data []byte) error {
	if b.closed.Load() {
		return io.ErrClosedPipe
	}
	if len(data) > 65535 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	packetLen := 2 + len(data)

	if len(b.buffer)+packetLen > b.maxSize || b.packetCount >= b.maxPackets {
		if err := b.flushLocked(); err != nil {
			return err
		}
	}

	b.buffer = append(b.buffer, byte(len(data)>>8), byte(len(data)))
	b.buffer = append(b.buffer, data...)
	b.packetCount++

	if b.packetCount == 1 {
		b.flushTimer = time.AfterFunc(b.flushDelay, func() {
			b.Flush()
		})
	}

	return nil
}

func (b *UDPBatcher) flushLocked() error {
	if len(b.buffer) == 0 {
		return nil
	}

	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.flushTimer = nil
	}

	_, err := b.stream.Write(b.buffer)
	b.buffer = b.buffer[:0]
	b.packetCount = 0
	return err
}

func (b *UDPBatcher) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked()
}

func (b *UDPBatcher) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.flushTimer != nil {
		b.flushTimer.Stop()
	}
	return b.flushLocked()
}

type RelayConnection struct {
	host      string
	conn      net.Conn
	session   *smux.Session
	active    atomic.Bool
	connected atomic.Bool
	mu        sync.RWMutex
}

type RelayManager struct {
	relays        []*RelayConnection
	activeRelay   atomic.Pointer[RelayConnection]
	token         string
	forwardRules  string
	strategy      string
	reconnectChan chan string
	ctx           context.Context
	cancel        context.CancelFunc
	useTLS        bool
}

type ActiveRelaySession struct {
	session   *smux.Session
	listeners []io.Closer
	mu        sync.Mutex
	closed    atomic.Bool
}

var (
	mode       = flag.String("mode", "", "Mode: relay or vpn")
	port       = flag.String("port", "", "Relay server port")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")
	useTLS     = flag.Bool("tls", false, "Enable TLS encryption with self-signed certificate (ChaCha20-Poly1305)")

	currentRelaySession   atomic.Pointer[ActiveRelaySession]
	currentRelaySessionMu sync.Mutex
)

// generateSelfSignedCert generates a self-signed certificate for TLS
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Self-Signed"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0"), net.ParseIP("::1"), net.ParseIP("::")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// getTLSConfig returns a TLS config for the server with ChaCha20-Poly1305
func getServerTLSConfig() (*tls.Config, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}, nil
}

// getClientTLSConfig returns a TLS config for the client with ChaCha20-Poly1305
func getClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
}

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")
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
	var listener net.Listener
	var err error

	if *useTLS {
		tlsConfig, err := getServerTLSConfig()
		if err != nil {
			log.Fatalf("Failed to create TLS config: %v", err)
		}

		tcpListener, err := createReusableListener("tcp", ":"+*port)
		if err != nil {
			log.Fatalf("Failed to start relay server: %v", err)
		}
		listener = tls.NewListener(tcpListener, tlsConfig)
		log.Printf("Relay server listening on :%s (TLS enabled, ChaCha20-Poly1305)", *port)
	} else {
		listener, err = createReusableListener("tcp", ":"+*port)
		if err != nil {
			log.Fatalf("Failed to start relay server: %v", err)
		}
		log.Printf("Relay server listening on :%s", *port)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go handleRelayConnection(ctx, conn)
	}
}

func closeCurrentSession() {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	session := currentRelaySession.Load()
	if session != nil && !session.closed.Swap(true) {
		session.mu.Lock()
		log.Printf("Closing previous session to allow immediate reconnection...")

		for _, l := range session.listeners {
			if l != nil {
				l.Close()
			}
		}
		session.listeners = nil

		if session.session != nil && !session.session.IsClosed() {
			session.session.Close()
		}
		session.mu.Unlock()

		currentRelaySession.Store(nil)
		log.Printf("Previous session closed, ports freed")
	}
}

func setCurrentSession(session *smux.Session) *ActiveRelaySession {
	currentRelaySessionMu.Lock()
	defer currentRelaySessionMu.Unlock()

	ars := &ActiveRelaySession{
		session:   session,
		listeners: make([]io.Closer, 0),
	}
	currentRelaySession.Store(ars)
	return ars
}

func (ars *ActiveRelaySession) addListener(l io.Closer) {
	if ars.closed.Load() {
		if l != nil {
			l.Close()
		}
		return
	}
	ars.mu.Lock()
	defer ars.mu.Unlock()
	if ars.closed.Load() {
		if l != nil {
			l.Close()
		}
		return
	}
	ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// For TLS connections, the underlying TCP connection is wrapped
	// We need to check if it's a TLS connection and get the underlying conn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	} else if tlsConn, ok := conn.(*tls.Conn); ok {
		// Complete TLS handshake
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
			return
		}
		// Log the cipher suite being used
		state := tlsConn.ConnectionState()
		log.Printf("TLS connection established with %s using %s", conn.RemoteAddr(), tls.CipherSuiteName(state.CipherSuite))
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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

	conn.SetReadDeadline(time.Time{})

	if _, err := conn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

	// Only close previous session AFTER successful authentication
	closeCurrentSession()

	lenBuf := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	ruleLen := binary.BigEndian.Uint16(lenBuf)
	if ruleLen == 0 {
		log.Printf("No forward rules received, keeping connection alive")
		<-ctx.Done()
		return
	}

	ruleBuf := make([]byte, ruleLen)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, ruleBuf); err != nil {
		log.Printf("Failed to read forward rules: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	parts := strings.Split(string(ruleBuf), "|")
	var forwardRules, forwardudpRules string
	if len(parts) >= 1 {
		forwardRules = parts[0]
	}
	if len(parts) >= 2 {
		forwardudpRules = parts[1]
	}
	log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(conn, smuxConfig)
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
		go startTCPForwarderWithListener(ctx, session, rule, listener)
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
		go startUDPForwarderWithConn(ctx, session, rule, udpConn)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if session.IsClosed() {
				log.Printf("Session closed")
				return
			}
		}
	}
}

func startTCPForwarderWithListener(ctx context.Context, session *smux.Session, rule ForwardRule, listener net.Listener) {
	defer listener.Close()

	log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if session.IsClosed() {
				return
			}
			log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
			return
		}

		go handleTCPForward(session, rule, conn)
	}
}

func handleTCPForward(session *smux.Session, rule ForwardRule, c net.Conn) {
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

	header := make([]byte, 0, 2+len(rule.targetPort))
	header = append(header, TCP_FORWARD)
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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		io.CopyBuffer(stream, c, *buf)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		io.CopyBuffer(c, stream, *buf)
		c.Close()
	}()

	wg.Wait()
}

func startUDPForwarderWithConn(ctx context.Context, session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()

	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := &sync.Map{}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UnixNano()
				sessions.Range(func(key, value interface{}) bool {
					sess := value.(*UDPSession)
					lastActive := sess.lastActive.Load()
					if now-lastActive > int64(2*time.Minute) {
						if sess.closed.CompareAndSwap(false, true) {
							if sess.batcher != nil {
								sess.batcher.Close()
							}
							sess.stream.Close()
							sessions.Delete(key)
						}
					}
					return true
				})
			}
		}
	}()

	buf := getBuffer()
	defer putBuffer(buf)

	for {
		select {
		case <-ctx.Done():
			sessions.Range(func(key, value interface{}) bool {
				sess := value.(*UDPSession)
				if sess.closed.CompareAndSwap(false, true) {
					if sess.batcher != nil {
						sess.batcher.Close()
					}
					sess.stream.Close()
				}
				return true
			})
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := conn.ReadFromUDP(*buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if session.IsClosed() {
				return
			}
			log.Printf("UDP read error on %s: %v", rule.srcPort, err)
			return
		}

		sessionKey := clientAddr.String()
		now := time.Now().UnixNano()

		if existing, ok := sessions.Load(sessionKey); ok {
			sess := existing.(*UDPSession)
			if !sess.closed.Load() {
				sess.lastActive.Store(now)
				if err := sess.batcher.Write((*buf)[:n]); err != nil {
					if sess.closed.CompareAndSwap(false, true) {
						sess.batcher.Close()
						sess.stream.Close()
						sessions.Delete(sessionKey)
					}
				}
				continue
			}
			sessions.Delete(sessionKey)
		}

		stream, err := session.OpenStream()
		if err != nil {
			log.Printf("Failed to open stream for UDP client %s: %v", sessionKey, err)
			continue
		}

		header := make([]byte, 0, 2+len(rule.targetPort))
		header = append(header, UDP_FORWARD)
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

		batcher := NewUDPBatcher(stream)
		sess := &UDPSession{
			conn:       conn,
			stream:     stream,
			clientAddr: clientAddr,
			batcher:    batcher,
		}
		sess.lastActive.Store(now)

		actual, loaded := sessions.LoadOrStore(sessionKey, sess)
		if loaded {
			batcher.Close()
			stream.Close()
			actualSess := actual.(*UDPSession)
			if !actualSess.closed.Load() {
				actualSess.lastActive.Store(now)
				if err := actualSess.batcher.Write((*buf)[:n]); err != nil {
					if actualSess.closed.CompareAndSwap(false, true) {
						actualSess.batcher.Close()
						actualSess.stream.Close()
						sessions.Delete(sessionKey)
					}
				}
			}
			continue
		}

		go udpReceiverWithBatcher(sessions, sessionKey, sess)

		if err := batcher.Write((*buf)[:n]); err != nil {
			if sess.closed.CompareAndSwap(false, true) {
				batcher.Close()
				stream.Close()
				sessions.Delete(sessionKey)
			}
		}
	}
}

func udpReceiverWithBatcher(sessions *sync.Map, sessionKey string, sess *UDPSession) {
	defer func() {
		if sess.closed.CompareAndSwap(false, true) {
			if sess.batcher != nil {
				sess.batcher.Close()
			}
			sess.stream.Close()
			sessions.Delete(sessionKey)
		}
	}()

	buf := getBuffer()
	defer putBuffer(buf)

	for {
		if sess.closed.Load() {
			return
		}

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(sess.stream, lenBuf); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(lenBuf)
		if int(length) > len(*buf) {
			return
		}

		if _, err := io.ReadFull(sess.stream, (*buf)[:length]); err != nil {
			return
		}

		sess.lastActive.Store(time.Now().UnixNano())
		if _, err := sess.conn.WriteToUDP((*buf)[:length], sess.clientAddr); err != nil {
			// Ignore write errors
		}
	}
}

func runVPN(ctx context.Context) {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
	log.Printf("Strategy: %s", *strategy)
	if *useTLS {
		log.Printf("TLS enabled (ChaCha20-Poly1305, no verification)")
	}

	forwardRules := *forward + "|" + *forwardudp

	vpnCtx, vpnCancel := context.WithCancel(ctx)
	manager := &RelayManager{
		relays:        make([]*RelayConnection, len(hosts)),
		token:         *token,
		forwardRules:  forwardRules,
		strategy:      *strategy,
		reconnectChan: make(chan string, len(hosts)*2), // Increased buffer to prevent blocking
		ctx:           vpnCtx,
		cancel:        vpnCancel,
		useTLS:        *useTLS,
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

	<-ctx.Done()
	vpnCancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All connections closed")
	case <-time.After(5 * time.Second):
		log.Println("Timeout waiting for connections to close")
	}
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	for {
		select {
		case <-rm.ctx.Done():
			return
		default:
		}

		log.Printf("[%s] Connecting to relay server...", relay.host)

		var conn net.Conn
		var err error

		// Use shorter timeout for faster failure detection
		dialer := net.Dialer{Timeout: 5 * time.Second}
		tcpConn, err := dialer.DialContext(rm.ctx, "tcp", relay.host)
		if err != nil {
			log.Printf("[%s] Failed to connect: %v. Retrying in 1s...", relay.host, err)
			relay.connected.Store(false)
			
			// Signal immediate retry for monitoring
			select {
			case rm.reconnectChan <- relay.host:
			default:
			}
			
			select {
			case <-rm.ctx.Done():
				return
			case <-time.After(1 * time.Second): // Changed from 2s to 1s
			}
			continue
		}

		if rm.useTLS {
			tlsConfig := getClientTLSConfig()
			tlsConn := tls.Client(tcpConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("[%s] TLS handshake failed: %v. Retrying in 1s...", relay.host, err)
				tcpConn.Close()
				relay.connected.Store(false)
				
				select {
				case rm.reconnectChan <- relay.host:
				default:
				}
				
				select {
				case <-rm.ctx.Done():
					return
				case <-time.After(1 * time.Second): // Changed from 2s to 1s
				}
				continue
			}
			state := tlsConn.ConnectionState()
			log.Printf("[%s] TLS connected using %s", relay.host, tls.CipherSuiteName(state.CipherSuite))
			conn = tlsConn
		} else {
			conn = tcpConn
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}

		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			
			select {
			case rm.reconnectChan <- relay.host:
			default:
			}
			
			select {
			case <-rm.ctx.Done():
				return
			case <-time.After(1 * time.Second): // Changed from 2s to 1s
			}
			continue
		}

		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Authentication failed or bad response: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			
			select {
			case rm.reconnectChan <- relay.host:
			default:
			}
			
			select {
			case <-rm.ctx.Done():
				return
			case <-time.After(1 * time.Second): // Changed from 2s to 1s
			}
			continue
		}

		ruleLen := make([]byte, 2)
		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			conn.Close()
			relay.connected.Store(false)
			continue
		}
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := conn.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send forward rules length: %v", relay.host, err)
			conn.Close()
			relay.connected.Store(false)
			
			select {
			case rm.reconnectChan <- relay.host:
			default:
			}
			
			select {
			case <-rm.ctx.Done():
				return
			case <-time.After(1 * time.Second): // Changed from 2s to 1s
			}
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := conn.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send forward rules: %v", relay.host, err)
				conn.Close()
				relay.connected.Store(false)
				
				select {
				case rm.reconnectChan <- relay.host:
				default:
				}
				
				select {
				case <-rm.ctx.Done():
					return
				case <-time.After(1 * time.Second): // Changed from 2s to 1s
				}
				continue
			}
		}

		conn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated", relay.host)

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
			
			select {
			case rm.reconnectChan <- relay.host:
			default:
			}
			
			select {
			case <-rm.ctx.Done():
				return
			case <-time.After(1 * time.Second): // Changed from 2s to 1s
			}
			continue
		}

		// Use write lock for setting connection state
		relay.mu.Lock()
		relay.conn = conn
		relay.session = session
		relay.mu.Unlock()
		relay.connected.Store(true)

		// Signal successful connection
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		rm.handleVPNSession(relay, session)

		// Cleanup with write lock
		relay.active.Store(false)
		relay.connected.Store(false)
		relay.mu.Lock()
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()

		session.Close()
		conn.Close()
		log.Printf("[%s] Connection lost. Reconnecting in 1s...", relay.host)

		// Signal disconnection
		select {
		case rm.reconnectChan <- relay.host:
		default:
		}

		select {
		case <-rm.ctx.Done():
			return
		case <-time.After(1 * time.Second): // Changed from 2s to 1s
		}
	}
}

func (rm *RelayManager) monitorRelays() {
	ticker := time.NewTicker(1 * time.Second) // Changed from 5s to 1s for faster detection
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.checkAndSwitchRelay()
		case <-rm.reconnectChan:
			// Immediate check on reconnection events
			rm.checkAndSwitchRelay()
		}
	}
}

func (r *RelayConnection) getSession() *smux.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.session
}

func (r *RelayConnection) isHealthy() bool {
	if !r.connected.Load() {
		return false
	}
	sess := r.getSession()
	return sess != nil && !sess.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
	if rm.strategy == "multi" {
		// In multi strategy, mark all healthy relays as active
		hasActive := false
		for _, relay := range rm.relays {
			if relay.isHealthy() {
				if !relay.active.Load() {
					relay.active.Store(true)
					log.Printf("[%s] Marked as ACTIVE (multi strategy)", relay.host)
				}
				hasActive = true
			} else {
				if relay.active.Load() {
					relay.active.Store(false)
					log.Printf("[%s] Marked as INACTIVE (disconnected)", relay.host)
				}
			}
		}
		if !hasActive {
			log.Printf("WARNING: No active relays available in multi strategy")
		}
		return
	}

	// Failover strategy
	currentRelay := rm.activeRelay.Load()

	// If current relay is healthy, keep it
	if currentRelay != nil && currentRelay.isHealthy() {
		return
	}

	// Current relay is unhealthy, deactivate it
	if currentRelay != nil {
		currentRelay.active.Store(false)
		log.Printf("[%s] Marked as inactive", currentRelay.host)
	}

	// Find first healthy relay for failover
	for _, relay := range rm.relays {
		if relay.isHealthy() {
			relay.active.Store(true)
			rm.activeRelay.Store(relay)
			log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
			return
		}
	}

	// No healthy relays available
	log.Printf("WARNING: No relay servers available, waiting for reconnection...")
}

func (rm *RelayManager) handleVPNSession(relay *RelayConnection, session *smux.Session) {
	for {
		select {
		case <-rm.ctx.Done():
			return
		default:
		}

		stream, err := session.AcceptStream()
		if err != nil {
			return
		}

		go rm.handleVPNStream(relay, stream)
	}
}

func (rm *RelayManager) handleVPNStream(relay *RelayConnection, s *smux.Stream) {
	defer s.Close()

	s.SetReadDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(s, header); err != nil {
		return
	}

	proto := header[0]
	portLen := header[1]
	if portLen == 0 || portLen > 64 {
		return
	}
	portBuf := make([]byte, portLen)
	if _, err := io.ReadFull(s, portBuf); err != nil {
		return
	}

	s.SetReadDeadline(time.Time{})

	targetPort := string(portBuf)

	if !relay.active.Load() {
		return
	}

	if proto == TCP_FORWARD {
		handleTCPStream(s, targetPort)
	} else if proto == UDP_FORWARD {
		handleUDPStream(s, targetPort)
	}
}

func handleTCPStream(stream *smux.Stream, targetPort string) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err := dialer.Dial("tcp", net.JoinHostPort("localhost", targetPort))
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetPort, err)
		return
	}
	defer target.Close()

	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		io.CopyBuffer(target, stream, *buf)
		target.Close()
	}()

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		io.CopyBuffer(stream, target, *buf)
		stream.Close()
	}()

	wg.Wait()
}

func handleUDPStream(stream *smux.Stream, targetPort string) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("localhost", targetPort))
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
	done := make(chan struct{})

	go func() {
		defer wg.Done()
		defer close(done)
		buf := getBuffer()
		defer putBuffer(buf)
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(*buf) {
				return
			}
			if _, err := io.ReadFull(stream, (*buf)[:length]); err != nil {
				return
			}
			if _, err := conn.Write((*buf)[:length]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		for {
			select {
			case <-done:
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(*buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			if n > 65535 {
				return
			}

			combined := make([]byte, 2+n)
			binary.BigEndian.PutUint16(combined[:2], uint16(n))
			copy(combined[2:], (*buf)[:n])

			if _, err := stream.Write(combined); err != nil {
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
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
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
			if err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					opErr = err
					return
				}
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			}); err != nil {
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
			if err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					opErr = err
					return
				}
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, &net.OpError{Op: "listen", Net: "udp", Err: io.ErrUnexpectedEOF}
	}
	return udpConn, nil
}
