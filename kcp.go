package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
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

	"github.com/golang/snappy"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	TCP_FORWARD  = 1
	UDP_FORWARD  = 2
	SO_REUSEPORT = 15

	// Copy buffer size — large enough to absorb V2Ray/Xray mux bursts
	// without fragmenting into tiny smux frames.
	copyBufSize = 256 * 1024
)

// ---------------------------------------------------------------------------
// Buffer pool — store []byte directly (not *[]byte) to avoid dangling pointer
// ---------------------------------------------------------------------------

var copyBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, copyBufSize)
	},
}

func getCopyBuf() []byte  { return copyBufPool.Get().([]byte) }
func putCopyBuf(buf []byte) { copyBufPool.Put(buf) } //nolint:staticcheck

// UDP frame header pool — avoids heap alloc per UDP packet on hot path
var udpHeaderPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2)
		return &b
	},
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
	lastActive time.Time
	closed     bool
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
	strategy      string
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
	port       = flag.String("port", "", "Relay server port (KCP/UDP)")
	host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple)")
	token      = flag.String("token", "", "Authentication token")
	forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
	forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
	strategy   = flag.String("strategy", "multi", "Strategy: multi or failover")

	// KCP tuning flags
	kcpMTU    = flag.Int("kcp-mtu", 1450, "KCP MTU (default 1450, higher payload ratio)")
	kcpSndWnd = flag.Int("kcp-sndwnd", 4096, "KCP send window size (packets)")
	kcpRcvWnd = flag.Int("kcp-rcvwnd", 4096, "KCP receive window size (packets)")
	sockBuf   = flag.Int("sockbuf", 33554432, "UDP socket buffer in bytes (default 32MB)")
	dscp      = flag.Int("dscp", 46, "DSCP value for KCP packets (46=EF for low latency)")

	// smux tuning
	smuxMaxRecv   = flag.Int("smux-recv-buf", 33554432, "smux session receive buffer (default 32MB)")
	smuxMaxStream = flag.Int("smux-stream-buf", 8388608, "smux per-stream buffer (default 8MB)")

	// Snappy flush interval
	snappyFlushInterval = flag.Duration("snappy-flush", 500*time.Microsecond,
		"How often the snappy writer is flushed (default 500µs; 0 = per-write)")

	currentRelaySession   *ActiveRelaySession
	currentRelaySessionMu sync.Mutex
)

// ---------------------------------------------------------------------------
// Snappy compressed stream wrapper
//
// The original code called writer.Flush() on every Write(), which meant one
// syscall (and one compressed block) per smux frame — destroying both
// compression ratio and throughput.
//
// Instead we flush on a background ticker. The ticker interval is tunable:
//   - 0  → synchronous flush (original behaviour, useful for debugging)
//   - 500µs → good balance for interactive + streaming workloads
//   - 1ms+  → better compression ratio at the cost of a little latency
//
// The stop channel is closed when the underlying connection is closed so the
// flush goroutine exits promptly and doesn't keep the conn alive.
// ---------------------------------------------------------------------------

type snappyConn struct {
	net.Conn
	reader *snappy.Reader
	writer *snappy.Writer
	mu     sync.Mutex // guards writer
	stop   chan struct{}
}

func newSnappyConn(conn net.Conn, flushInterval time.Duration) *snappyConn {
	sc := &snappyConn{
		Conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
		stop:   make(chan struct{}),
	}

	if flushInterval > 0 {
		go sc.flushLoop(flushInterval)
	}
	return sc
}

func (sc *snappyConn) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-sc.stop:
			return
		case <-ticker.C:
			sc.mu.Lock()
			_ = sc.writer.Flush()
			sc.mu.Unlock()
		}
	}
}

func (sc *snappyConn) Read(p []byte) (int, error) {
	// snappy.Reader is not concurrency-safe but Read is only called from
	// smux's single read goroutine, so no lock needed here.
	return sc.reader.Read(p)
}

func (sc *snappyConn) Write(p []byte) (int, error) {
	sc.mu.Lock()
	n, err := sc.writer.Write(p)
	if *snappyFlushInterval == 0 {
		// Synchronous mode: flush immediately (safe under the lock)
		if err == nil {
			err = sc.writer.Flush()
		}
	}
	sc.mu.Unlock()
	return n, err
}

func (sc *snappyConn) Close() error {
	select {
	case <-sc.stop:
	default:
		close(sc.stop)
	}
	sc.mu.Lock()
	_ = sc.writer.Flush()
	sc.mu.Unlock()
	return sc.Conn.Close()
}

// ---------------------------------------------------------------------------
// TLS helpers — ephemeral self-signed ECDSA P-256 cert, TLS 1.3 only
// ---------------------------------------------------------------------------

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func serverTLSConfig() *tls.Config {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

func clientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
}

// ---------------------------------------------------------------------------
// KCP helpers
// ---------------------------------------------------------------------------

// tuneKCP sets bandwidth-efficient parameters.
//
// nodelay=1   — enable nodelay mode
// interval=10 — internal update timer 10ms (better for streaming vs 20ms)
// resend=2    — fast retransmit on 2 duplicate ACKs
// nc=1        — no congestion window
func tuneKCP(conn *kcp.UDPSession) {
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetMtu(*kcpMTU)
	conn.SetWindowSize(*kcpSndWnd, *kcpRcvWnd)
	// ACKNoDelay=false: batch ACKs — cuts overhead packet count significantly
	conn.SetACKNoDelay(false)
	conn.SetStreamMode(true)

	conn.SetDSCP(*dscp)

	conn.SetReadBuffer(*sockBuf)
	conn.SetWriteBuffer(*sockBuf)
}

// ---------------------------------------------------------------------------
// smux config shared by both sides
// ---------------------------------------------------------------------------

func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = *smuxMaxRecv
	cfg.MaxStreamBuffer = *smuxMaxStream
	// 64KB frames — matches our 256KB copy buf better; fewer header bytes/byte
	cfg.MaxFrameSize = 65535
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required")
	}

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
// Relay (server) side
// ---------------------------------------------------------------------------

func runRelay() {
	listener, err := kcp.ListenWithOptions(":"+*port, nil, 0, 0)
	if err != nil {
		log.Fatalf("Failed to start KCP relay server: %v", err)
	}
	defer listener.Close()

	if err := listener.SetReadBuffer(*sockBuf); err != nil {
		log.Printf("Warning: failed to set UDP read buffer: %v", err)
	}
	if err := listener.SetWriteBuffer(*sockBuf); err != nil {
		log.Printf("Warning: failed to set UDP write buffer: %v", err)
	}
	listener.SetDSCP(*dscp)

	tlsCfg := serverTLSConfig()

	log.Printf("Relay server listening on KCP :%s (TLS 1.3 + Snappy, flush=%v)", *port, *snappyFlushInterval)

	for {
		kcpConn, err := listener.AcceptKCP()
		if err != nil {
			log.Printf("KCP accept error: %v", err)
			continue
		}
		tuneKCP(kcpConn)

		go handleRelayConnection(kcpConn, tlsCfg)
	}
}

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

func handleRelayConnection(kcpConn *kcp.UDPSession, tlsCfg *tls.Config) {
	// Wrap KCP in TLS (server side)
	tlsConn := tls.Server(kcpConn, tlsCfg)
	defer tlsConn.Close()

	// TLS handshake with timeout
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed from %s: %v", kcpConn.RemoteAddr(), err)
		return
	}
	tlsConn.SetDeadline(time.Time{})

	// Authenticate: read exact token
	tokLen := len(*token)
	tokBuf := make([]byte, tokLen)
	if _, err := io.ReadFull(tlsConn, tokBuf); err != nil {
		log.Printf("Auth read error from %s: %v", kcpConn.RemoteAddr(), err)
		return
	}
	if string(tokBuf) != *token {
		log.Printf("Authentication failed from %s", kcpConn.RemoteAddr())
		return
	}

	// Close existing session BEFORE sending OK to free ports
	closeCurrentSession()

	if _, err := tlsConn.Write([]byte("OK")); err != nil {
		log.Printf("Failed to write OK to %s: %v", kcpConn.RemoteAddr(), err)
		return
	}
	log.Printf("VPN authenticated: %s (KCP+TLS+Snappy)", kcpConn.RemoteAddr())

	// Receive forward rules
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, lenBuf); err != nil {
		log.Printf("Failed to read forward rules length: %v", err)
		return
	}
	ruleLen := binary.BigEndian.Uint16(lenBuf)
	if ruleLen == 0 {
		log.Printf("No forward rules received, connection idle")
		return
	}
	ruleBuf := make([]byte, ruleLen)
	if _, err := io.ReadFull(tlsConn, ruleBuf); err != nil {
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
	log.Printf("Forward rules — TCP: %s, UDP: %s", forwardRules, forwardudpRules)

	// Wrap TLS conn in snappy compression, then hand to smux
	compressedConn := newSnappyConn(tlsConn, *snappyFlushInterval)

	// smux session over Snappy-over-TLS-over-KCP
	session, err := smux.Server(compressedConn, newSmuxConfig())
	if err != nil {
		log.Printf("Failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	activeSession := setCurrentSession(session)

	tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
	udpRules := parseForwardRules(forwardudpRules, UDP_FORWARD)

	var forwarderWg sync.WaitGroup

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

	for !session.IsClosed() {
		time.Sleep(1 * time.Second)
	}

	forwarderWg.Wait()
	log.Printf("Session closed")
}

// ---------------------------------------------------------------------------
// TCP forwarding (relay side)
// ---------------------------------------------------------------------------

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

			if tcpConn, ok := c.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
			}

			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for TCP forward: %v", err)
				return
			}
			defer stream.Close()

			// Write coalesced header — combine type+port into a single write
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				return
			}
			header := make([]byte, 0, 2+len(portBytes))
			header = append(header, TCP_FORWARD, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
				return
			}

			bidirectionalCopy(c, stream)
		}(conn)
	}
}

// bidirectionalCopy performs full-duplex copy with pooled large buffers.
// putCopyBuf is called before closeOnDone so the buffer is returned to the
// pool as soon as the copy direction finishes, not after the close completes.
func bidirectionalCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer) {
		defer wg.Done()
		buf := getCopyBuf()
		_, _ = io.CopyBuffer(dst, src, buf)
		putCopyBuf(buf)
		closeOnDone.Close()
	}

	go copyDir(b, a, b)
	go copyDir(a, b, a)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// UDP forwarding (relay side)
// ---------------------------------------------------------------------------

func startUDPForwarderWithConn(session *smux.Session, rule ForwardRule, conn *net.UDPConn) {
	defer conn.Close()
	log.Printf("Forwarding UDP %s -> %s", rule.srcPort, rule.targetPort)

	sessions := make(map[string]*UDPSession)
	var sessionsMu sync.Mutex

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

	buf := make([]byte, 65535)
	// Reusable 2-byte length prefix buffer — avoids alloc per UDP packet
	var lenPrefix [2]byte

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

			// Write coalesced header — type+port in one write
			portBytes := []byte(rule.targetPort)
			if len(portBytes) > 255 {
				stream.Close()
				continue
			}
			header := make([]byte, 0, 2+len(portBytes))
			header = append(header, UDP_FORWARD, byte(len(portBytes)))
			header = append(header, portBytes...)
			if _, err := stream.Write(header); err != nil {
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
		// Use stack-allocated header — no heap alloc per packet
		binary.BigEndian.PutUint16(lenPrefix[:], uint16(n))
		if _, err := sess.stream.Write(lenPrefix[:]); err != nil {
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
		if _, err := sess.stream.Write(buf[:n]); err != nil {
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

// ---------------------------------------------------------------------------
// VPN (client) side
// ---------------------------------------------------------------------------

func runVPN() {
	if *strategy != "multi" && *strategy != "failover" {
		log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
	}

	hosts := strings.Split(*host, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	log.Printf("VPN mode — %d relay(s): %v  strategy: %s", len(hosts), hosts, *strategy)

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

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
	tlsCfg := clientTLSConfig()

	for {
		log.Printf("[%s] Connecting via KCP+TLS+Snappy...", relay.host)

		kcpConn, err := kcp.DialWithOptions(relay.host, nil, 0, 0)
		if err != nil {
			log.Printf("[%s] KCP dial failed: %v. Retrying in 2s...", relay.host, err)
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		tuneKCP(kcpConn)

		tlsConn := tls.Client(kcpConn, tlsCfg)

		tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[%s] TLS handshake failed: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		if _, err := tlsConn.Write([]byte(rm.token)); err != nil {
			log.Printf("[%s] Failed to send token: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("[%s] Auth failed or bad response: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		if len(rm.forwardRules) > 0xFFFF {
			log.Printf("[%s] Forward rules too long", relay.host)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		ruleLen := make([]byte, 2)
		binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
		if _, err := tlsConn.Write(ruleLen); err != nil {
			log.Printf("[%s] Failed to send rules length: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}
		if len(rm.forwardRules) > 0 {
			if _, err := tlsConn.Write([]byte(rm.forwardRules)); err != nil {
				log.Printf("[%s] Failed to send rules: %v", relay.host, err)
				tlsConn.Close()
				relay.connected.Store(false)
				time.Sleep(2 * time.Second)
				continue
			}
		}

		tlsConn.SetDeadline(time.Time{})

		log.Printf("[%s] Connected and authenticated (KCP+TLS+Snappy)", relay.host)

		// Wrap TLS conn in snappy compression, then hand to smux
		compressedConn := newSnappyConn(tlsConn, *snappyFlushInterval)

		// smux client over Snappy-over-TLS-over-KCP
		session, err := smux.Client(compressedConn, newSmuxConfig())
		if err != nil {
			log.Printf("[%s] smux session failed: %v", relay.host, err)
			tlsConn.Close()
			relay.connected.Store(false)
			time.Sleep(2 * time.Second)
			continue
		}

		relay.mu.Lock()
		relay.conn = tlsConn
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
		tlsConn.Close()
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
					log.Printf("[%s] Marked as ACTIVE (multi)", relay.host)
				}
			} else {
				if relay.active.Load() {
					relay.active.Store(false)
					log.Printf("[%s] Marked as INACTIVE", relay.host)
				}
			}
		}
		return
	}

	// Failover
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
			log.Printf("[%s] Promoted to ACTIVE (failover)", relay.host)
			return
		}
	}

	if currentRelay != nil {
		log.Printf("WARNING: No relay servers available")
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

			switch proto {
			case TCP_FORWARD:
				handleTCPStream(s, targetPort)
			case UDP_FORWARD:
				handleUDPStream(s, targetPort)
			}
		}(stream)
	}
	streamWg.Wait()
}

// ---------------------------------------------------------------------------
// Stream handlers (VPN side — connects to local services)
// ---------------------------------------------------------------------------

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

	// stream → UDP
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

	// UDP → stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		var lenPrefix [2]byte
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := conn.Read(buf)
			if err != nil {
				stream.Close()
				return
			}
			// Stack-allocated header — no heap alloc per packet
			binary.BigEndian.PutUint16(lenPrefix[:], uint16(n))
			if _, err := stream.Write(lenPrefix[:]); err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseForwardRules(rules string, proto int) []ForwardRule {
	if rules == "" {
		return nil
	}
	var result []ForwardRule
	for _, pair := range strings.Split(rules, ";") {
		parts := strings.Split(pair, ",")
		if len(parts) == 2 {
			src := strings.TrimSpace(parts[0])
			tgt := strings.TrimSpace(parts[1])
			if src != "" && tgt != "" {
				result = append(result, ForwardRule{srcPort: src, targetPort: tgt, proto: proto})
			}
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
