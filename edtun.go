package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Custom binary multiplexer — replaces smux to avoid DPI fingerprinting.
//
// Frame format (7-byte header + payload):
//   [type:1][streamID:4][length:2][payload:0..65535]
//
// Frame types:
//   0x00  DATA   – stream payload
//   0x01  SYN    – open a new stream
//   0x02  FIN    – close a stream
//   0x03  PING   – keepalive request
//   0x04  PONG   – keepalive response
// ---------------------------------------------------------------------------

const (
	frameData uint8 = iota
	frameSYN
	frameFIN
	framePING
	framePONG

	frameHeaderSize = 7
	maxFramePayload = 65535
	acceptBacklog   = 256
)

// MuxConfig holds tunables for the multiplexer.
type MuxConfig struct {
	MaxReceiveBuffer  int
	MaxStreamBuffer   int
	KeepAliveInterval time.Duration
	KeepAliveTimeout  time.Duration
}

// DefaultMuxConfig returns sensible defaults.
func DefaultMuxConfig() *MuxConfig {
	return &MuxConfig{
		MaxReceiveBuffer:  4 * 1024 * 1024,
		MaxStreamBuffer:   1 * 1024 * 1024,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
	}
}

// Mux multiplexes streams over a single net.Conn.
type Mux struct {
	conn       net.Conn
	config     *MuxConfig
	nextID     uint32
	streams    map[uint32]*MuxStream
	mu         sync.Mutex
	acceptCh   chan *MuxStream
	closedFlag int32
	closeCh    chan struct{}
	closeOnce  sync.Once
	writeMu    sync.Mutex
	lastRecv   time.Time
	lastRecvMu sync.Mutex
}

// MuxStream is one logical stream inside a Mux.
type MuxStream struct {
	id      uint32
	mux     *Mux
	buf     bytes.Buffer
	mu      sync.Mutex
	cond    *sync.Cond
	rClosed bool
	closed  bool
}

func newMux(conn net.Conn, cfg *MuxConfig) *Mux {
	m := &Mux{
		conn:     conn,
		config:   cfg,
		streams:  make(map[uint32]*MuxStream),
		acceptCh: make(chan *MuxStream, acceptBacklog),
		closeCh:  make(chan struct{}),
		lastRecv: time.Now(),
	}
	go m.readLoop()
	go m.keepAliveLoop()
	return m
}

func NewMuxClient(conn net.Conn, cfg *MuxConfig) *Mux { return newMux(conn, cfg) }
func NewMuxServer(conn net.Conn, cfg *MuxConfig) *Mux { return newMux(conn, cfg) }

func (m *Mux) IsClosed() bool { return atomic.LoadInt32(&m.closedFlag) == 1 }

func (m *Mux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		atomic.StoreInt32(&m.closedFlag, 1)
		close(m.closeCh)
		m.mu.Lock()
		for _, s := range m.streams {
			s.mu.Lock()
			s.closed = true
			s.cond.Broadcast()
			s.mu.Unlock()
		}
		m.streams = make(map[uint32]*MuxStream)
		m.mu.Unlock()
		err = m.conn.Close()
	})
	return err
}

func (m *Mux) OpenStream() (*MuxStream, error) {
	if m.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	sid := atomic.AddUint32(&m.nextID, 1)
	s := m.newStream(sid)
	m.mu.Lock()
	m.streams[sid] = s
	m.mu.Unlock()
	if err := m.sendFrame(frameSYN, sid, nil); err != nil {
		m.mu.Lock()
		delete(m.streams, sid)
		m.mu.Unlock()
		return nil, err
	}
	return s, nil
}

func (m *Mux) AcceptStream() (*MuxStream, error) {
	select {
	case s, ok := <-m.acceptCh:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return s, nil
	case <-m.closeCh:
		return nil, io.ErrClosedPipe
	}
}

func (m *Mux) newStream(id uint32) *MuxStream {
	s := &MuxStream{id: id, mux: m}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (m *Mux) sendFrame(ftype uint8, sid uint32, payload []byte) error {
	if m.IsClosed() {
		return io.ErrClosedPipe
	}
	frame := make([]byte, frameHeaderSize+len(payload))
	frame[0] = ftype
	binary.BigEndian.PutUint32(frame[1:5], sid)
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
	if len(payload) > 0 {
		copy(frame[frameHeaderSize:], payload)
	}
	m.writeMu.Lock()
	_, err := m.conn.Write(frame)
	m.writeMu.Unlock()
	return err
}

func (m *Mux) readLoop() {
	defer m.Close()
	hdr := make([]byte, frameHeaderSize)
	for {
		if _, err := io.ReadFull(m.conn, hdr); err != nil {
			return
		}
		ftype := hdr[0]
		sid := binary.BigEndian.Uint32(hdr[1:5])
		length := binary.BigEndian.Uint16(hdr[5:7])

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(m.conn, payload); err != nil {
				return
			}
		}

		m.lastRecvMu.Lock()
		m.lastRecv = time.Now()
		m.lastRecvMu.Unlock()

		switch ftype {
		case frameSYN:
			s := m.newStream(sid)
			m.mu.Lock()
			m.streams[sid] = s
			m.mu.Unlock()
			select {
			case m.acceptCh <- s:
			case <-m.closeCh:
				return
			}
		case frameData:
			m.mu.Lock()
			s, ok := m.streams[sid]
			m.mu.Unlock()
			if ok && len(payload) > 0 {
				s.mu.Lock()
				if !s.closed && !s.rClosed {
					s.buf.Write(payload)
				}
				s.cond.Broadcast()
				s.mu.Unlock()
			}
		case frameFIN:
			m.mu.Lock()
			s, ok := m.streams[sid]
			m.mu.Unlock()
			if ok {
				s.mu.Lock()
				s.rClosed = true
				s.cond.Broadcast()
				s.mu.Unlock()
			}
		case framePING:
			_ = m.sendFrame(framePONG, 0, nil)
		case framePONG:
			// liveness already updated
		}
	}
}

func (m *Mux) keepAliveLoop() {
	ticker := time.NewTicker(m.config.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.closeCh:
			return
		case <-ticker.C:
			if err := m.sendFrame(framePING, 0, nil); err != nil {
				m.Close()
				return
			}
			m.lastRecvMu.Lock()
			last := m.lastRecv
			m.lastRecvMu.Unlock()
			if time.Since(last) > m.config.KeepAliveTimeout {
				log.Printf("Mux keepalive timeout")
				m.Close()
				return
			}
		}
	}
}

func (s *MuxStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.buf.Len() == 0 {
		if s.closed || s.rClosed {
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	return s.buf.Read(p)
}

func (s *MuxStream) Write(p []byte) (int, error) {
	if s.isClosed() {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > maxFramePayload {
			n = maxFramePayload
		}
		if err := s.mux.sendFrame(frameData, s.id, p[written:written+n]); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (s *MuxStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	_ = s.mux.sendFrame(frameFIN, s.id, nil)
	s.mux.mu.Lock()
	delete(s.mux.streams, s.id)
	s.mux.mu.Unlock()
	return nil
}

func (s *MuxStream) isClosed() bool {
	s.mu.Lock()
	c := s.closed
	s.mu.Unlock()
	return c || s.mux.IsClosed()
}

// ---------------------------------------------------------------------------
// TUN interface
// ---------------------------------------------------------------------------

const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
	cTUNSETIFF = 0x400454ca
	tunMTU     = 1500
	tunChanBuf = 1024
)

type ifreqFlags struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

func openTUN(name string) (*os.File, string, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreqFlags
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cTUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, "", fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}
	ifName := strings.TrimRight(string(req.Name[:]), "\x00")
	return os.NewFile(uintptr(fd), "/dev/net/tun"), ifName, nil
}

func configureTUN(ifName, ipCIDR string, mtu int) error {
	cmds := [][]string{
		{"ip", "addr", "flush", "dev", ifName},
		{"ip", "addr", "add", ipCIDR, "dev", ifName},
		{"ip", "link", "set", "dev", ifName, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "link", "set", "dev", ifName, "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", c, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// tunReader continuously reads IP packets from the TUN device and sends
// them into a channel. Runs for the lifetime of the TUN fd.
func tunReader(tun *os.File, ch chan<- []byte) {
	buf := make([]byte, tunMTU+128)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Printf("TUN read error: %v", err)
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case ch <- pkt:
		default:
			// Drop under back-pressure rather than blocking the TUN device.
		}
	}
}

// relayTUNTraffic shuttles packets between the TUN channel and a mux
// stream until the stream dies. Each packet is length-prefixed on the wire:
//
//	[2-byte big-endian length][raw IP packet]
func relayTUNTraffic(tun *os.File, stream *MuxStream, tunPkts <-chan []byte) {
	done := make(chan struct{})

	// stream → TUN
	go func() {
		defer close(done)
		lenBuf := make([]byte, 2)
		pktBuf := make([]byte, 65536)
		for {
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)
			if int(pktLen) > len(pktBuf) {
				return
			}
			if _, err := io.ReadFull(stream, pktBuf[:pktLen]); err != nil {
				return
			}
			if _, err := tun.Write(pktBuf[:pktLen]); err != nil {
				log.Printf("TUN write error: %v", err)
				return
			}
		}
	}()

	// TUN → stream
	for {
		select {
		case pkt, ok := <-tunPkts:
			if !ok {
				return
			}
			frame := make([]byte, 2+len(pkt))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(pkt)))
			copy(frame[2:], pkt)
			if _, err := stream.Write(frame); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

// drainChannel empties a packet channel of stale data.
func drainChannel(ch <-chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Relay mode
// ---------------------------------------------------------------------------

func runRelay() {
	// Create TUN interface.
	tunFile, ifName, err := openTUN(*tunDev)
	if err != nil {
		log.Fatalf("Failed to create TUN: %v", err)
	}
	defer tunFile.Close()

	ipCIDR := relayIP + "/" + subnetBits
	if err := configureTUN(ifName, ipCIDR, tunMTU); err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}
	log.Printf("TUN %s up with %s", ifName, ipCIDR)

	tunPkts := make(chan []byte, tunChanBuf)
	go tunReader(tunFile, tunPkts)

	// TCP listener with SO_REUSEADDR.
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var se error
			c.Control(func(fd uintptr) {
				se = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			return se
		},
	}
	listener, err := lc.Listen(nil, "tcp", ":"+*port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	log.Printf("Relay listening on :%s", *port)

	// Track current session so a new VPN client kicks the old one.
	var (
		curSession *Mux
		curMu      sync.Mutex
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}

		// Authenticate.
		tokBuf := make([]byte, len(*token))
		if _, err := io.ReadFull(conn, tokBuf); err != nil {
			log.Printf("Auth read error from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		if string(tokBuf) != *token {
			log.Printf("Auth failed from %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Kill previous session to free the TUN reader consumer.
		curMu.Lock()
		if curSession != nil && !curSession.IsClosed() {
			log.Printf("Closing previous session for new client")
			curSession.Close()
		}
		curMu.Unlock()

		// Respond OK.
		if _, err := conn.Write([]byte("OK")); err != nil {
			conn.Close()
			continue
		}
		log.Printf("VPN client authenticated: %s", conn.RemoteAddr())

		cfg := DefaultMuxConfig()
		session := NewMuxServer(conn, cfg)

		curMu.Lock()
		curSession = session
		curMu.Unlock()

		// Drain stale packets before starting new relay.
		drainChannel(tunPkts)

		// Run session handler in a goroutine so we can accept the next client
		// immediately if this one drops.
		go func(s *Mux, c net.Conn) {
			defer func() {
				s.Close()
				c.Close()
				curMu.Lock()
				if curSession == s {
					curSession = nil
				}
				curMu.Unlock()
				log.Printf("VPN client disconnected: %s", c.RemoteAddr())
			}()

			stream, err := s.AcceptStream()
			if err != nil {
				log.Printf("Failed to accept TUN stream: %v", err)
				return
			}
			defer stream.Close()

			log.Printf("TUN tunnel established with %s", c.RemoteAddr())
			relayTUNTraffic(tunFile, stream, tunPkts)
		}(session, conn)
	}
}

// ---------------------------------------------------------------------------
// VPN mode
// ---------------------------------------------------------------------------

func runVPN() {
	// Create TUN interface.
	tunFile, ifName, err := openTUN(*tunDev)
	if err != nil {
		log.Fatalf("Failed to create TUN: %v", err)
	}
	defer tunFile.Close()

	ipCIDR := vpnIP + "/" + subnetBits
	if err := configureTUN(ifName, ipCIDR, tunMTU); err != nil {
		log.Fatalf("Failed to configure TUN: %v", err)
	}
	log.Printf("TUN %s up with %s", ifName, ipCIDR)

	tunPkts := make(chan []byte, tunChanBuf)
	go tunReader(tunFile, tunPkts)

	// Reconnect loop.
	for {
		log.Printf("Connecting to relay %s ...", *host)

		conn, err := net.DialTimeout("tcp", *host, 10*time.Second)
		if err != nil {
			log.Printf("Connect failed: %v. Retrying in 2s...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}

		// Authenticate.
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(*token)); err != nil {
			log.Printf("Token send failed: %v", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		okBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
			log.Printf("Auth failed: %v", err)
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}
		conn.SetDeadline(time.Time{})

		log.Printf("Authenticated to relay %s", *host)

		cfg := DefaultMuxConfig()
		session := NewMuxClient(conn, cfg)

		stream, err := session.OpenStream()
		if err != nil {
			log.Printf("Failed to open TUN stream: %v", err)
			session.Close()
			conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		log.Printf("TUN tunnel established")

		// Drain stale packets before relaying.
		drainChannel(tunPkts)

		relayTUNTraffic(tunFile, stream, tunPkts)

		stream.Close()
		session.Close()
		conn.Close()
		log.Printf("Connection lost. Reconnecting in 2s...")
		time.Sleep(2 * time.Second)
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const (
	relayIP    = "192.168.100.1"
	vpnIP      = "192.168.100.2"
	subnetBits = "24"
)

var (
	mode   = flag.String("mode", "", "Mode: relay or vpn")
	port   = flag.String("port", "", "Relay server listen port")
	host   = flag.String("host", "", "Relay server host:port")
	token  = flag.String("token", "", "Authentication token")
	tunDev = flag.String("tun", "edtun0", "TUN device name")
)

func main() {
	flag.Parse()

	if *token == "" {
		log.Fatal("-token is required")
	}

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("-port is required for relay mode")
		}
		runRelay()
	case "vpn":
		if *host == "" {
			log.Fatal("-host is required for vpn mode")
		}
		runVPN()
	default:
		log.Fatal("Invalid -mode. Use 'relay' or 'vpn'")
	}
}
