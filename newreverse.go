package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/edthepurple/utls"
)

// ---------------------------------------------------------------------------
// Binary frame protocol
// Wire format: [Cmd:1][StreamID:4][Length:4][PadLen:1][Payload:Length][Padding:PadLen]
//
// Commands:
//   0x01 SYN_TCP   – open a new TCP stream  (payload = target port ASCII)
//   0x02 DATA      – carry stream payload (TCP or single UDP dgram)
//   0x03 FIN       – close a stream
//   0x04 PING      – keepalive request
//   0x05 PONG      – keepalive reply
//   0x06 SYN_UDP   – open a new UDP stream  (payload = target port ASCII)
// ---------------------------------------------------------------------------

const (
	cmdSYN_TCP byte = 0x01
	cmdDATA    byte = 0x02
	cmdFIN     byte = 0x03
	cmdPING    byte = 0x04
	cmdPONG    byte = 0x05
	cmdSYN_UDP byte = 0x06

	frameHeader  = 10         // 1 + 4 + 4 + 1 (cmd + streamID + length + padLen)
	maxPayload   = 64 << 10   // 64 KiB
	maxPadding   = 255        // 0–255 random bytes per frame
	streamBufCap = 256        // channel depth per stream
	pingInterval = 15 * time.Second
	handshakeMax = 512        // increased for multi-port handshake

	udpBufSize    = 65535
	udpIdleExpiry = 90 * time.Second
	udpSweep      = 30 * time.Second

	// Tuning knobs
	socketBufSize = 4 << 20   // 4 MiB SO_RCVBUF / SO_SNDBUF
	copyBufSize   = 64 << 10  // 64 KiB io.CopyBuffer size
	readBufSize   = 256 << 10 // 256 KiB bufio.Reader for tunnel conn

	// Auth
	nonceSize   = 32
	macSize     = 32 // SHA-256 output
	authTimeout = 5 * time.Second
)

// ---------------------------------------------------------------------------
// Port mapping
// ---------------------------------------------------------------------------

// portMapping represents a relay-listen-port → vpn-forward-port pair.
type portMapping struct {
	relayPort string // port the relay listens on (source)
	vpnPort   string // port the VPN forwards to on localhost (target)
}

// parsePortMappings parses the CLI format:
//
//	"8443"                → [{8443, 8443}]
//	"8443,8444"           → [{8443, 8444}]
//	"8443,8444;8445,8446" → [{8443, 8444}, {8445, 8446}]
func parsePortMappings(s string) []portMapping {
	if s == "" {
		return nil
	}
	var out []portMapping
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, ",", 2)
		if len(fields) == 1 {
			out = append(out, portMapping{fields[0], fields[0]})
		} else {
			out = append(out, portMapping{
				relayPort: strings.TrimSpace(fields[0]),
				vpnPort:   strings.TrimSpace(fields[1]),
			})
		}
	}
	return out
}

// encodePortMappings serialises mappings for the handshake wire format.
// Example: "8443>8444,8445>8446"
func encodePortMappings(m []portMapping) string {
	parts := make([]string, len(m))
	for i, pm := range m {
		parts[i] = pm.relayPort + ">" + pm.vpnPort
	}
	return strings.Join(parts, ",")
}

// decodePortMappings parses the wire format back into a slice.
func decodePortMappings(s string) []portMapping {
	if s == "" {
		return nil
	}
	var out []portMapping
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, ">", 2)
		if len(fields) == 2 {
			out = append(out, portMapping{
				relayPort: fields[0],
				vpnPort:   fields[1],
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Buffer pools – reduce GC pressure on the hot path
// ---------------------------------------------------------------------------

var payloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPayload)
		return &b
	},
}

func getPayloadBuf() *[]byte  { return payloadPool.Get().(*[]byte) }
func putPayloadBuf(b *[]byte) { payloadPool.Put(b) }

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

func getCopyBuf() *[]byte  { return copyBufPool.Get().(*[]byte) }
func putCopyBuf(b *[]byte) { copyBufPool.Put(b) }

var frameHdrPool = sync.Pool{
	New: func() any {
		b := make([]byte, frameHeader)
		return &b
	},
}

// ---------------------------------------------------------------------------
// TCP tuning helper
// ---------------------------------------------------------------------------

func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
	tc.SetReadBuffer(socketBufSize)
	tc.SetWriteBuffer(socketBufSize)
}

func tuneTCPListener(ln net.Listener) {
	if tl, ok := ln.(*net.TCPListener); ok {
		if rc, err := tl.SyscallConn(); err == nil {
			rc.Control(func(fd uintptr) {
				setSockBuf(fd, socketBufSize)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Random padding helper
// ---------------------------------------------------------------------------

func randPadLen() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

// ---------------------------------------------------------------------------
// Frame I/O – padding-aware
// ---------------------------------------------------------------------------

type frame struct {
	cmd      byte
	streamID uint32
	payload  []byte
}

func writeFrame(w io.Writer, mu *sync.Mutex, f frame, padding bool) error {
	plen := len(f.payload)
	padLen := byte(0)
	if padding {
		padLen = randPadLen()
	}

	total := frameHeader + plen + int(padLen)

	if plen <= 4096 {
		buf := make([]byte, total)
		buf[0] = f.cmd
		binary.BigEndian.PutUint32(buf[1:5], f.streamID)
		binary.BigEndian.PutUint32(buf[5:9], uint32(plen))
		buf[9] = padLen
		copy(buf[frameHeader:], f.payload)
		if padLen > 0 {
			rand.Read(buf[frameHeader+plen:])
		}
		mu.Lock()
		_, err := w.Write(buf)
		mu.Unlock()
		return err
	}

	hdrp := frameHdrPool.Get().(*[]byte)
	hdr := *hdrp
	hdr[0] = f.cmd
	binary.BigEndian.PutUint32(hdr[1:5], f.streamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(plen))
	hdr[9] = padLen

	var pad []byte
	if padLen > 0 {
		pad = make([]byte, padLen)
		rand.Read(pad)
	}

	mu.Lock()
	var err error
	if tc, ok := w.(*net.TCPConn); ok {
		bufs := net.Buffers{hdr, f.payload}
		if padLen > 0 {
			bufs = append(bufs, pad)
		}
		_, err = bufs.WriteTo(tc)
	} else {
		_, err = w.Write(hdr)
		if err == nil && plen > 0 {
			_, err = w.Write(f.payload)
		}
		if err == nil && padLen > 0 {
			_, err = w.Write(pad)
		}
	}
	mu.Unlock()

	frameHdrPool.Put(hdrp)
	return err
}

func readFrame(r io.Reader) (frame, error) {
	hdrp := frameHdrPool.Get().(*[]byte)
	hdr := *hdrp
	_, err := io.ReadFull(r, hdr)
	if err != nil {
		frameHdrPool.Put(hdrp)
		return frame{}, err
	}

	f := frame{
		cmd:      hdr[0],
		streamID: binary.BigEndian.Uint32(hdr[1:5]),
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	padLen := hdr[9]
	frameHdrPool.Put(hdrp)

	if length > maxPayload {
		return frame{}, fmt.Errorf("frame too large: %d", length)
	}
	if length > 0 {
		f.payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return frame{}, err
		}
	}
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(r, pad); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 Authentication
// ---------------------------------------------------------------------------

func computeMAC(token, nonce []byte) []byte {
	h := hmac.New(sha256.New, token)
	h.Write(nonce)
	return h.Sum(nil)
}

func authRelay(conn net.Conn, token string) error {
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		conn.Close()
		return fmt.Errorf("generate nonce: %w", err)
	}
	if _, err := conn.Write(nonce); err != nil {
		conn.Close()
		return fmt.Errorf("send nonce: %w", err)
	}

	clientMAC := make([]byte, macSize)
	if _, err := io.ReadFull(conn, clientMAC); err != nil {
		conn.Close()
		return fmt.Errorf("read MAC: %w", err)
	}

	expected := computeMAC([]byte(token), nonce)
	if !hmac.Equal(clientMAC, expected) {
		conn.Close()
		return fmt.Errorf("invalid token (bad HMAC)")
	}
	return nil
}

func authVPN(conn net.Conn, token string) error {
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		conn.Close()
		return fmt.Errorf("read nonce: %w", err)
	}

	mac := computeMAC([]byte(token), nonce)
	if _, err := conn.Write(mac); err != nil {
		conn.Close()
		return fmt.Errorf("send MAC: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// TLS — relay (server) side
// ---------------------------------------------------------------------------

func loadOrGenerateTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		log.Printf("tls: loaded certificate from %s", certFile)
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	log.Println("tls: generating self-signed EC P-256 certificate")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"edtunnel"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("0.0.0.0"), net.IPv6zero},
		DNSNames:     []string{"*"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
		MinVersion: tls.VersionTLS12,
	}, nil
}

// ---------------------------------------------------------------------------
// TLS — VPN (client) side: uTLS Chrome fingerprint
// ---------------------------------------------------------------------------

func dialTLS(rawConn net.Conn, sni string, insecure bool) (net.Conn, error) {
	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
	}, utls.HelloChrome_Auto)

	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	st := tlsConn.ConnectionState()
	log.Printf("tls: Chrome fingerprint, SNI=%s, cipher=0x%04x, proto=%s",
		sni, st.CipherSuite, st.NegotiatedProtocol)
	return tlsConn, nil
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

type streamKind int

const (
	kindTCP streamKind = iota
	kindUDP
)

type stream struct {
	id         uint32
	kind       streamKind
	targetPort string // VPN-side target port (carried in SYN payload)
	sess       *session
	dataCh     chan []byte
	readBuf    []byte
	finSent    int32
}

func newStream(id uint32, k streamKind, s *session) *stream {
	return &stream{
		id:     id,
		kind:   k,
		sess:   s,
		dataCh: make(chan []byte, streamBufCap),
	}
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		data, ok := <-s.dataCh
		if !ok {
			return 0, io.EOF
		}
		s.readBuf = data
	}
}

func (s *stream) ReadDatagram() ([]byte, error) {
	data, ok := <-s.dataCh
	if !ok {
		return nil, io.EOF
	}
	return data, nil
}

func (s *stream) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		end := sent + maxPayload
		if end > len(p) {
			end = len(p)
		}
		chunk := make([]byte, end-sent)
		copy(chunk, p[sent:end])
		if err := writeFrame(s.sess.rawConn, &s.sess.writeMu, frame{
			cmd: cmdDATA, streamID: s.id, payload: chunk,
		}, s.sess.padding); err != nil {
			return sent, err
		}
		sent = end
	}
	return sent, nil
}

func (s *stream) WriteDatagram(p []byte) error {
	buf := make([]byte, len(p))
	copy(buf, p)
	return writeFrame(s.sess.rawConn, &s.sess.writeMu, frame{
		cmd: cmdDATA, streamID: s.id, payload: buf,
	}, s.sess.padding)
}

func (s *stream) Close() error {
	if atomic.CompareAndSwapInt32(&s.finSent, 0, 1) {
		_ = writeFrame(s.sess.rawConn, &s.sess.writeMu, frame{
			cmd: cmdFIN, streamID: s.id,
		}, s.sess.padding)
	}
	s.sess.removeStream(s.id)
	return nil
}

func (s *stream) deliver(data []byte) {
	defer func() { recover() }()
	s.dataCh <- data
}

func (s *stream) closePipe() {
	defer func() { recover() }()
	close(s.dataCh)
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

type session struct {
	rawConn  net.Conn
	bufR     *bufio.Reader
	writeMu  sync.Mutex
	streams  sync.Map
	acceptCh chan *stream
	nextID   atomic.Uint32
	closed   int32
	done     chan struct{}
	doneOnce sync.Once
	padding  bool
}

func newSession(conn net.Conn, padding bool) *session {
	tuneTCP(conn)
	return &session{
		rawConn:  conn,
		bufR:     bufio.NewReaderSize(conn, readBufSize),
		acceptCh: make(chan *stream, 128),
		done:     make(chan struct{}),
		padding:  padding,
	}
}

func (s *session) recvLoop() {
	defer s.Close()
	for {
		f, err := readFrame(s.bufR)
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 0 {
				log.Printf("session: read error: %v", err)
			}
			return
		}
		switch f.cmd {
		case cmdSYN_TCP, cmdSYN_UDP:
			k := kindTCP
			if f.cmd == cmdSYN_UDP {
				k = kindUDP
			}
			st := newStream(f.streamID, k, s)
			// SYN payload carries the VPN-side target port.
			st.targetPort = string(f.payload)
			s.streams.Store(f.streamID, st)
			select {
			case s.acceptCh <- st:
			default:
				log.Printf("session: accept queue full, dropping stream %d", f.streamID)
				st.Close()
			}

		case cmdDATA:
			if v, ok := s.streams.Load(f.streamID); ok {
				v.(*stream).deliver(f.payload)
			}

		case cmdFIN:
			if v, ok := s.streams.Load(f.streamID); ok {
				v.(*stream).closePipe()
				s.streams.Delete(f.streamID)
			}

		case cmdPING:
			_ = writeFrame(s.rawConn, &s.writeMu, frame{cmd: cmdPONG}, s.padding)

		case cmdPONG:
			// ack
		}
	}
}

func (s *session) keepalive() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := writeFrame(s.rawConn, &s.writeMu, frame{cmd: cmdPING}, s.padding); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

// OpenStream opens a TCP stream.  vpnPort is encoded in the SYN payload so
// the VPN side knows which localhost port to forward to.
func (s *session) OpenStream(vpnPort string) (*stream, error) {
	return s.openStreamCmd(cmdSYN_TCP, kindTCP, vpnPort)
}

func (s *session) OpenUDPStream(vpnPort string) (*stream, error) {
	return s.openStreamCmd(cmdSYN_UDP, kindUDP, vpnPort)
}

func (s *session) openStreamCmd(cmd byte, k streamKind, vpnPort string) (*stream, error) {
	id := s.nextID.Add(1)
	st := newStream(id, k, s)
	st.targetPort = vpnPort
	s.streams.Store(id, st)
	if err := writeFrame(s.rawConn, &s.writeMu, frame{
		cmd: cmd, streamID: id, payload: []byte(vpnPort),
	}, s.padding); err != nil {
		s.streams.Delete(id)
		return nil, err
	}
	return st, nil
}

func (s *session) AcceptStream() (*stream, error) {
	select {
	case st, ok := <-s.acceptCh:
		if !ok {
			return nil, io.EOF
		}
		return st, nil
	case <-s.done:
		return nil, io.EOF
	}
}

func (s *session) removeStream(id uint32) {
	if v, ok := s.streams.LoadAndDelete(id); ok {
		v.(*stream).closePipe()
	}
}

func (s *session) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	s.doneOnce.Do(func() { close(s.done) })
	s.streams.Range(func(k, v any) bool {
		v.(*stream).closePipe()
		s.streams.Delete(k)
		return true
	})
	close(s.acceptCh)
	return s.rawConn.Close()
}

func (s *session) Done() <-chan struct{} { return s.done }

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

type relayConfig struct {
	port     string
	token    string
	useTLS   bool
	certFile string
	keyFile  string
	padding  bool
}

func runRelay(cfg relayConfig) {
	ln, err := net.Listen("tcp", ":"+cfg.port)
	if err != nil {
		log.Fatalf("relay: listen :%s: %v", cfg.port, err)
	}
	tuneTCPListener(ln)

	var tlsConf *tls.Config
	if cfg.useTLS {
		tlsConf, err = loadOrGenerateTLSConfig(cfg.certFile, cfg.keyFile)
		if err != nil {
			log.Fatalf("relay: tls: %v", err)
		}
	}

	var features []string
	if cfg.useTLS {
		features = append(features, "tls")
	}
	if cfg.token != "" {
		features = append(features, "hmac-auth")
	}
	if cfg.padding {
		features = append(features, "padding")
	}
	if len(features) == 0 {
		features = append(features, "no security")
	}
	log.Printf("relay: listening on :%s [%s]", cfg.port, strings.Join(features, " + "))

	for {
		rawConn, err := ln.Accept()
		if err != nil {
			log.Printf("relay: accept: %v", err)
			continue
		}
		tuneTCP(rawConn)
		log.Printf("relay: tunnel from %s", rawConn.RemoteAddr())

		go func() {
			var conn net.Conn = rawConn
			if tlsConf != nil {
				tlsConn := tls.Server(rawConn, tlsConf)
				tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					log.Printf("relay: tls handshake from %s: %v",
						rawConn.RemoteAddr(), err)
					rawConn.Close()
					return
				}
				tlsConn.SetDeadline(time.Time{})
				log.Printf("relay: tls OK from %s", rawConn.RemoteAddr())
				conn = tlsConn
			}
			handleTunnel(conn, cfg.token, cfg.padding)
		}()
	}
}

// Handshake wire format: "tcp:8443>8444,8445>8446 udp:9000>9001\n"
func handleTunnel(tunnelConn net.Conn, token string, padding bool) {
	// --- Authentication ---
	if token != "" {
		if err := authRelay(tunnelConn, token); err != nil {
			log.Printf("relay: auth failed from %s: %v",
				tunnelConn.RemoteAddr(), err)
			return
		}
		log.Printf("relay: auth OK from %s", tunnelConn.RemoteAddr())
	}

	// --- Port handshake ---
	buf := make([]byte, handshakeMax)
	n, err := tunnelConn.Read(buf)
	if err != nil {
		log.Printf("relay: handshake read: %v", err)
		tunnelConn.Close()
		return
	}
	line := strings.TrimSpace(string(buf[:n]))
	if line == "" {
		log.Printf("relay: empty handshake")
		tunnelConn.Close()
		return
	}

	var tcpMappings, udpMappings []portMapping
	for _, field := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(field, "tcp:"):
			tcpMappings = decodePortMappings(strings.TrimPrefix(field, "tcp:"))
		case strings.HasPrefix(field, "udp:"):
			udpMappings = decodePortMappings(strings.TrimPrefix(field, "udp:"))
		}
	}

	if len(tcpMappings) == 0 && len(udpMappings) == 0 {
		log.Printf("relay: no port mappings in handshake: %q", line)
		tunnelConn.Close()
		return
	}

	sess := newSession(tunnelConn, padding)
	go sess.recvLoop()
	go sess.keepalive()

	// Collect all listeners so we can close them when the session dies.
	var tcpListeners []net.Listener
	var udpListeners []*net.UDPConn

	cleanup := func() {
		for _, ln := range tcpListeners {
			ln.Close()
		}
		for _, uc := range udpListeners {
			uc.Close()
		}
	}

	// --- TCP listeners ---
	for _, pm := range tcpMappings {
		tcpLn, err := net.Listen("tcp", ":"+pm.relayPort)
		if err != nil {
			log.Printf("relay: listen tcp :%s: %v", pm.relayPort, err)
			cleanup()
			sess.Close()
			return
		}
		tuneTCPListener(tcpLn)
		tcpListeners = append(tcpListeners, tcpLn)
		log.Printf("relay: TCP :%s → tunnel → :%s", pm.relayPort, pm.vpnPort)

		go relayTCPAcceptLoop(sess, tcpLn, pm)
	}

	// --- UDP listeners ---
	for _, pm := range udpMappings {
		addr, err := net.ResolveUDPAddr("udp", ":"+pm.relayPort)
		if err != nil {
			log.Printf("relay: resolve udp :%s: %v", pm.relayPort, err)
			cleanup()
			sess.Close()
			return
		}
		uc, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Printf("relay: listen udp :%s: %v", pm.relayPort, err)
			cleanup()
			sess.Close()
			return
		}
		uc.SetReadBuffer(socketBufSize)
		uc.SetWriteBuffer(socketBufSize)
		udpListeners = append(udpListeners, uc)
		log.Printf("relay: UDP :%s → tunnel → :%s", pm.relayPort, pm.vpnPort)

		go relayUDPListener(sess, uc, pm)
	}

	// Wait for session to die, then close all listeners.
	<-sess.Done()
	cleanup()
	log.Printf("relay: tunnel from %s closed", tunnelConn.RemoteAddr())
}

func relayTCPAcceptLoop(sess *session, ln net.Listener, pm portMapping) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-sess.Done():
				log.Printf("relay: tunnel closed, stopping tcp :%s", pm.relayPort)
			default:
				log.Printf("relay: tcp accept :%s: %v", pm.relayPort, err)
			}
			return
		}
		tuneTCP(clientConn)
		go relayTCPClient(sess, clientConn, pm.vpnPort)
	}
}

func relayTCPClient(sess *session, clientConn net.Conn, vpnPort string) {
	st, err := sess.OpenStream(vpnPort)
	if err != nil {
		log.Printf("relay: tcp open stream: %v", err)
		clientConn.Close()
		return
	}
	log.Printf("relay: tcp stream %d ← %s → :%s", st.id, clientConn.RemoteAddr(), vpnPort)
	bridgeTCP(clientConn, st)
	log.Printf("relay: tcp stream %d closed", st.id)
}

// ---------------------------------------------------------------------------
// Relay — UDP session table (per-listener)
// ---------------------------------------------------------------------------

type udpSession struct {
	stream     *stream
	remoteAddr *net.UDPAddr
	lastSeen   atomic.Int64
}

func relayUDPListener(sess *session, udpConn *net.UDPConn, pm portMapping) {
	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	go func() {
		t := time.NewTicker(udpSweep)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				now := time.Now().UnixNano()
				mu.Lock()
				for key, us := range sessions {
					if now-us.lastSeen.Load() > int64(udpIdleExpiry) {
						log.Printf("relay: udp session %s (stream %d) expired",
							key, us.stream.id)
						us.stream.Close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			case <-sess.Done():
				return
			}
		}
	}()

	buf := make([]byte, udpBufSize)
	for {
		n, raddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-sess.Done():
			default:
				log.Printf("relay: udp read: %v", err)
			}
			return
		}

		key := raddr.String()

		mu.Lock()
		us, exists := sessions[key]
		if !exists {
			st, err := sess.OpenUDPStream(pm.vpnPort)
			if err != nil {
				mu.Unlock()
				log.Printf("relay: udp open stream: %v", err)
				continue
			}
			us = &udpSession{stream: st, remoteAddr: raddr}
			sessions[key] = us
			log.Printf("relay: udp stream %d ← %s → :%s (new)",
				st.id, key, pm.vpnPort)

			go func(us *udpSession, key string) {
				for {
					dgram, err := us.stream.ReadDatagram()
					if err != nil {
						break
					}
					if _, err := udpConn.WriteToUDP(dgram, us.remoteAddr); err != nil {
						break
					}
				}
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
				log.Printf("relay: udp stream %d return path closed", us.stream.id)
			}(us, key)
		}
		mu.Unlock()

		us.lastSeen.Store(time.Now().UnixNano())
		if err := us.stream.WriteDatagram(buf[:n]); err != nil {
			log.Printf("relay: udp stream %d write: %v", us.stream.id, err)
		}
	}
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

type vpnConfig struct {
	relayHost  string
	relayPort  string
	tcpForward string // raw CLI value, e.g. "8443,8444;8445,8446"
	udpForward string // raw CLI value
	token      string
	useTLS     bool
	sni        string
	insecure   bool
	padding    bool
}

func runVPN(cfg vpnConfig) {
	for {
		if err := vpnSession(cfg); err != nil {
			log.Printf("vpn: session error: %v", err)
		}
		log.Println("vpn: reconnecting in 2s...")
		time.Sleep(2 * time.Second)
	}
}

func vpnSession(cfg vpnConfig) error {
	tcpMappings := parsePortMappings(cfg.tcpForward)
	udpMappings := parsePortMappings(cfg.udpForward)

	if len(tcpMappings) == 0 && len(udpMappings) == 0 {
		return fmt.Errorf("no port mappings configured")
	}

	addr := net.JoinHostPort(cfg.relayHost, cfg.relayPort)
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	tuneTCP(rawConn)
	log.Printf("vpn: connected to relay %s", addr)

	// --- TLS ---
	var conn net.Conn = rawConn
	if cfg.useTLS {
		sni := cfg.sni
		if sni == "" {
			sni = cfg.relayHost
		}
		conn, err = dialTLS(rawConn, sni, cfg.insecure)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}

	// --- Authentication ---
	if cfg.token != "" {
		if err := authVPN(conn, cfg.token); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		log.Printf("vpn: auth completed")
	}

	// --- Handshake: send port mappings ---
	var parts []string
	if len(tcpMappings) > 0 {
		parts = append(parts, "tcp:"+encodePortMappings(tcpMappings))
	}
	if len(udpMappings) > 0 {
		parts = append(parts, "udp:"+encodePortMappings(udpMappings))
	}
	handshake := strings.Join(parts, " ")
	if _, err := conn.Write([]byte(handshake + "\n")); err != nil {
		conn.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	for _, pm := range tcpMappings {
		log.Printf("vpn: TCP relay :%s → localhost:%s", pm.relayPort, pm.vpnPort)
	}
	for _, pm := range udpMappings {
		log.Printf("vpn: UDP relay :%s → localhost:%s", pm.relayPort, pm.vpnPort)
	}

	sess := newSession(conn, cfg.padding)
	go sess.recvLoop()
	go sess.keepalive()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			sess.Close()
			return fmt.Errorf("accept stream: %w", err)
		}
		// Target port was carried in the SYN payload.
		switch st.kind {
		case kindTCP:
			go vpnForwardTCP(st)
		case kindUDP:
			go vpnForwardUDP(st)
		}
	}
}

func vpnForwardTCP(st *stream) {
	port := st.targetPort
	if port == "" {
		log.Printf("vpn: tcp stream %d: no target port in SYN", st.id)
		st.Close()
		return
	}
	localConn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Printf("vpn: tcp stream %d: dial localhost:%s: %v", st.id, port, err)
		st.Close()
		return
	}
	tuneTCP(localConn)
	log.Printf("vpn: tcp stream %d → localhost:%s", st.id, port)
	bridgeTCP(localConn, st)
	log.Printf("vpn: tcp stream %d closed", st.id)
}

func vpnForwardUDP(st *stream) {
	port := st.targetPort
	if port == "" {
		log.Printf("vpn: udp stream %d: no target port in SYN", st.id)
		st.Close()
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
	if err != nil {
		log.Printf("vpn: udp resolve localhost:%s: %v", port, err)
		st.Close()
		return
	}
	localConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Printf("vpn: udp stream %d: dial localhost:%s: %v", st.id, port, err)
		st.Close()
		return
	}
	localConn.SetReadBuffer(socketBufSize)
	localConn.SetWriteBuffer(socketBufSize)
	defer localConn.Close()
	defer st.Close()
	log.Printf("vpn: udp stream %d → localhost:%s", st.id, port)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			dgram, err := st.ReadDatagram()
			if err != nil {
				localConn.Close()
				return
			}
			if _, err := localConn.Write(dgram); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, udpBufSize)
		for {
			localConn.SetReadDeadline(time.Now().Add(udpIdleExpiry))
			n, err := localConn.Read(buf)
			if err != nil {
				st.Close()
				return
			}
			if err := st.WriteDatagram(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("vpn: udp stream %d closed", st.id)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bridgeTCP(conn net.Conn, st *stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bp := getCopyBuf()
		io.CopyBuffer(st, conn, *bp)
		putCopyBuf(bp)
		st.Close()
	}()

	go func() {
		defer wg.Done()
		bp := getCopyBuf()
		io.CopyBuffer(conn, st, *bp)
		putCopyBuf(bp)
		conn.Close()
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host (vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
	forwardTCP := flag.String("forward", "", "TCP port forwarding: relay,vpn[;relay2,vpn2;...] (vpn mode)")
	forwardUDP := flag.String("forwardudp", "", "UDP port forwarding: relay,vpn[;relay2,vpn2;...] (vpn mode)")
	token := flag.String("token", "", "Shared secret for HMAC-SHA256 authentication")
	useTLS := flag.Bool("tls", false, "Enable TLS (relay: server-side, vpn: uTLS Chrome fingerprint)")
	certFile := flag.String("cert", "", "TLS certificate PEM file (relay; auto-generated if omitted)")
	keyFile := flag.String("key", "", "TLS private key PEM file (relay; auto-generated if omitted)")
	sni := flag.String("sni", "", "TLS SNI hostname sent in ClientHello (vpn; defaults to -host)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (vpn)")
	padding := flag.Bool("padding", false, "Random 0-255 byte padding per frame (obfuscates frame sizes)")
	flag.Parse()

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("relay mode requires -port")
		}
		runRelay(relayConfig{
			port:     *port,
			token:    *token,
			useTLS:   *useTLS,
			certFile: *certFile,
			keyFile:  *keyFile,
			padding:  *padding,
		})
	case "vpn":
		if *host == "" || *port == "" || *forwardTCP == "" {
			log.Fatal("vpn mode requires -host, -port, and -forward")
		}
		runVPN(vpnConfig{
			relayHost:  *host,
			relayPort:  *port,
			tcpForward: *forwardTCP,
			udpForward: *forwardUDP,
			token:      *token,
			useTLS:     *useTLS,
			sni:        *sni,
			insecure:   *insecure,
			padding:    *padding,
		})
	default:
		log.Fatal("usage: -mode relay|vpn")
	}
}
