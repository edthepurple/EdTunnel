// edtunnel – a tiny high‑performance TCP/UDP tunnel written in Go.
//
// USAGE
// Server: ./edtunnel -mode server -port 8081 -token <shared-secret>
//
// Client (binds on *all* interfaces, not only 127.0.0.1):
// ./edtunnel -mode client \
//   -host <server:8081> \
//   -token <shared-secret> \
//   -forward 5000,5000 \          // TCP localPort → remotePort
//   -forwardudp 51820,51820       // UDP localPort → remotePort
//
// The client may be started on any host; the listeners are created with
// "0.0.0.0:port", i.e. they accept connections from every network interface.

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/* -------------------------------------------------------------------------
Frame definition & helpers
---------------------------------------------------------------------- */

const (
	FRAME_AUTH          = 0
	FRAME_AUTH_RESP     = 1
	FRAME_CONFIG        = 2
	FRAME_TCP_CONNECT   = 3
	FRAME_TCP_DATA      = 4
	FRAME_TCP_CLOSE     = 5
	FRAME_UDP_DATA      = 6
	FRAME_UDP_DATA_BACK = 7
	FRAME_PING          = 8 // #11: keepalive
	FRAME_PONG          = 9

	PROTO_TCP = 0
	PROTO_UDP = 1

	headerSize = 12 // 1+1+2+4+4 bytes

	pingInterval = 15 * time.Second // #11: heartbeat interval
	pingTimeout  = 45 * time.Second // #11: dead connection detection
)

type Frame struct {
	Type      uint8
	ForwardID uint16
	StreamID  uint32
	Length    uint32
	Payload   []byte
}

/* -------------------------------------------------------------------------
#1: Buffer pools – reusable read buffers and payload slices
---------------------------------------------------------------------- */

var (
	// Pool for 16KB read buffers (TCP relay loops)
	buf16KPool = sync.Pool{
		New: func() any {
			b := make([]byte, 16*1024)
			return &b
		},
	}

	// Pool for 64KB read buffers (UDP)
	buf64KPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}

	// Pool for combined write buffers (header + up to 16KB payload)
	// Sized for the common case; larger payloads allocate fresh.
	writeBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, headerSize+16*1024)
			return &b
		},
	}
)

func getBuf16K() *[]byte  { return buf16KPool.Get().(*[]byte) }
func putBuf16K(b *[]byte) { buf16KPool.Put(b) }

func getBuf64K() *[]byte  { return buf64KPool.Get().(*[]byte) }
func putBuf64K(b *[]byte) { buf64KPool.Put(b) }

/* -------------------------------------------------------------------------
#2 + #4: writeFrame – stack‑allocated header, single coalesced write
---------------------------------------------------------------------- */

func writeFrame(w io.Writer, f *Frame) error {
	// #2: stack‑allocated header (no heap escape for the array itself)
	var hdr [headerSize]byte
	hdr[0] = f.Type
	// hdr[1] is reserved (0)
	binary.BigEndian.PutUint16(hdr[2:4], f.ForwardID)
	binary.BigEndian.PutUint32(hdr[4:8], f.StreamID)
	binary.BigEndian.PutUint32(hdr[8:12], f.Length)

	if f.Length == 0 {
		// header-only frame – single write
		_, err := w.Write(hdr[:])
		return err
	}

	// #4: coalesced write – header + payload in one syscall
	total := headerSize + int(f.Length)

	// Try to use the pool for common sizes
	if total <= headerSize+16*1024 {
		bp := writeBufPool.Get().(*[]byte)
		buf := (*bp)[:total]
		copy(buf[:headerSize], hdr[:])
		copy(buf[headerSize:], f.Payload)
		_, err := w.Write(buf)
		writeBufPool.Put(bp)
		return err
	}

	// Large payload: use net.Buffers (writev scatter-gather) to avoid copying
	bufs := net.Buffers{hdr[:], f.Payload}
	_, err := bufs.WriteTo(w)
	return err
}

// readFrame reads a complete frame from r.
// #1 / #3: header uses stack array; payload pooling left to the caller
// since payloads are handed off to Write() calls and ownership transfers.
func readFrame(r io.Reader) (*Frame, error) {
	var hdr [headerSize]byte // #2: stack-allocated
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	typ := hdr[0]
	fwd := binary.BigEndian.Uint16(hdr[2:4])
	str := binary.BigEndian.Uint32(hdr[4:8])
	l := binary.BigEndian.Uint32(hdr[8:12])

	var payload []byte
	if l > 0 {
		payload = make([]byte, l)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{
		Type:      typ,
		ForwardID: fwd,
		StreamID:  str,
		Length:    l,
		Payload:   payload,
	}, nil
}

/* -------------------------------------------------------------------------
#5: TCP_NODELAY helper
---------------------------------------------------------------------- */

func setNoDelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
}

/* -------------------------------------------------------------------------
Configuration handling (client side)
---------------------------------------------------------------------- */

type portMapping struct {
	local  uint16
	remote uint16
}

type portMappingList []portMapping

func (p *portMappingList) String() string {
	var parts []string
	for _, m := range *p {
		parts = append(parts, fmt.Sprintf("%d,%d", m.local, m.remote))
	}
	return strings.Join(parts, " ")
}

func (p *portMappingList) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) != 2 {
		return fmt.Errorf("invalid mapping %q, expected local,remote", value)
	}
	loc, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("invalid local port %q: %w", parts[0], err)
	}
	rem, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("invalid remote port %q: %w", parts[1], err)
	}
	*p = append(*p, portMapping{local: uint16(loc), remote: uint16(rem)})
	return nil
}

/* -------------------------------------------------------------------------
Server side
---------------------------------------------------------------------- */

type forwardConfig struct {
	proto      string // "tcp" or "udp"
	remotePort uint16
}

type clientSession struct {
	conn       net.Conn
	token      string
	writeCh    chan *Frame
	forwards   map[uint16]forwardConfig                  // forwardID → config
	tcpStreams sync.Map                                   // #7: lock-free lookups for TCP data path
	udpSockets map[uint16]map[uint32]*net.UDPConn         // forwardID → streamID → UDP conn
	mu         sync.RWMutex                               // #7: RWMutex, now only protects forwards + udpSockets
	wg         sync.WaitGroup
	lastPong   atomic.Int64                               // #11: unix timestamp of last pong
	done       chan struct{}                               // signal shutdown
}

/* ---------------------------------------------------------------------
Server – accept client connections
--------------------------------------------------------------------- */

func runServer(listenPort int, token string) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		log.Fatalf("listen %d: %v", listenPort, err)
	}
	defer ln.Close()
	log.Printf("Server listening on :%d", listenPort)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		setNoDelay(c) // #5
		go handleClient(c, token)
	}
}

/* ---------------------------------------------------------------------
Per‑client handling (authentication + multiplexing)
--------------------------------------------------------------------- */

func handleClient(conn net.Conn, token string) {
	defer conn.Close()
	sess := &clientSession{
		conn:       conn,
		token:      token,
		writeCh:    make(chan *Frame, 1024),
		forwards:   make(map[uint16]forwardConfig),
		udpSockets: make(map[uint16]map[uint32]*net.UDPConn),
		done:       make(chan struct{}),
	}
	sess.lastPong.Store(time.Now().Unix())

	// writer goroutine (serialises all writes to the tunnel)
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		for f := range sess.writeCh {
			if err := writeFrame(sess.conn, f); err != nil {
				log.Printf("write to client %s failed: %v", sess.conn.RemoteAddr(), err)
				return
			}
		}
	}()

	// #11: heartbeat – server sends PINGs, expects PONGs
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Check if client is still alive
				if time.Since(time.Unix(sess.lastPong.Load(), 0)) > pingTimeout {
					log.Printf("client %s timed out (no pong)", sess.conn.RemoteAddr())
					sess.conn.Close() // will break the read loop
					return
				}
				select {
				case sess.writeCh <- &Frame{Type: FRAME_PING}:
				default:
					// write channel full, connection probably stalled
				}
			case <-sess.done:
				return
			}
		}
	}()

	/* ------------------ authentication ------------------ */
	auth, err := readFrame(sess.conn)
	if err != nil {
		log.Printf("auth read error from %s: %v", sess.conn.RemoteAddr(), err)
		close(sess.done)
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	if auth.Type != FRAME_AUTH {
		log.Printf("expected AUTH frame, got %d", auth.Type)
		close(sess.done)
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	if string(auth.Payload) != sess.token {
		sess.writeCh <- &Frame{
			Type:    FRAME_AUTH_RESP,
			Length:  uint32(len("FAIL")),
			Payload: []byte("FAIL"),
		}
		close(sess.done)
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	sess.writeCh <- &Frame{
		Type:    FRAME_AUTH_RESP,
		Length:  uint32(len("OK")),
		Payload: []byte("OK"),
	}

	/* ------------------ main frame loop ------------------ */
	for {
		f, err := readFrame(sess.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("read error from %s: %v", sess.conn.RemoteAddr(), err)
			}
			break
		}
		if err := sess.handleFrame(f); err != nil {
			log.Printf("frame handling error: %v", err)
			break
		}
	}
	// clean‑up
	close(sess.done)
	close(sess.writeCh)
	sess.cleanup()
	sess.wg.Wait()
	log.Printf("session %s closed", sess.conn.RemoteAddr())
}

/* ---------------------------------------------------------------------
Clean‑up all active streams / sockets
--------------------------------------------------------------------- */

func (s *clientSession) cleanup() {
	// TCP streams stored in sync.Map
	s.tcpStreams.Range(func(key, value any) bool {
		value.(net.Conn).Close()
		s.tcpStreams.Delete(key)
		return true
	})
	// UDP sockets still under RWMutex
	s.mu.Lock()
	for _, perForward := range s.udpSockets {
		for _, conn := range perForward {
			conn.Close()
		}
	}
	s.udpSockets = nil
	s.mu.Unlock()
}

/* ---------------------------------------------------------------------
Frame dispatcher (server side)
--------------------------------------------------------------------- */

func (s *clientSession) handleFrame(f *Frame) error {
	switch f.Type {

	// #11: keepalive
	case FRAME_PONG:
		s.lastPong.Store(time.Now().Unix())
		return nil

	case FRAME_PING:
		// Client sent us a ping (shouldn't normally happen, but be graceful)
		select {
		case s.writeCh <- &Frame{Type: FRAME_PONG}:
		default:
		}
		return nil

	case FRAME_CONFIG:
		if len(f.Payload) != 3 {
			return fmt.Errorf("invalid CONFIG payload length %d", len(f.Payload))
		}
		protoByte := f.Payload[0]
		remotePort := binary.BigEndian.Uint16(f.Payload[1:3])
		var cfg forwardConfig
		if protoByte == PROTO_TCP {
			cfg.proto = "tcp"
		} else if protoByte == PROTO_UDP {
			cfg.proto = "udp"
		} else {
			return fmt.Errorf("unknown protocol byte %d", protoByte)
		}
		cfg.remotePort = remotePort

		s.mu.Lock()
		s.forwards[f.ForwardID] = cfg
		if cfg.proto == "udp" {
			if _, ok := s.udpSockets[f.ForwardID]; !ok {
				s.udpSockets[f.ForwardID] = make(map[uint32]*net.UDPConn)
			}
		}
		s.mu.Unlock()
		return nil

	case FRAME_TCP_CONNECT:
		s.mu.RLock() // #7: RLock for read-only access
		cfg, ok := s.forwards[f.ForwardID]
		s.mu.RUnlock()
		if !ok {
			return fmt.Errorf("unknown forward ID %d for TCP_CONNECT", f.ForwardID)
		}
		if cfg.proto != "tcp" {
			return fmt.Errorf("forward ID %d is not TCP", f.ForwardID)
		}
		remote := fmt.Sprintf("127.0.0.1:%d", cfg.remotePort)
		remoteConn, err := net.Dial("tcp", remote)
		if err != nil {
			s.writeCh <- &Frame{Type: FRAME_TCP_CLOSE, StreamID: f.StreamID}
			return fmt.Errorf("dial %s: %w", remote, err)
		}
		setNoDelay(remoteConn) // #5

		// #7: sync.Map for tcpStreams
		s.tcpStreams.Store(f.StreamID, remoteConn)

		// pump data from remote → client
		s.wg.Add(1)
		go func(sid uint32, rc net.Conn) {
			defer s.wg.Done()
			defer rc.Close()
			bp := getBuf16K() // #1: pooled buffer
			buf := *bp
			defer putBuf16K(bp)
			for {
				n, err := rc.Read(buf)
				if n > 0 {
					data := make([]byte, n)
					copy(data, buf[:n])
					s.writeCh <- &Frame{
						Type:     FRAME_TCP_DATA,
						StreamID: sid,
						Length:   uint32(n),
						Payload:  data,
					}
				}
				if err != nil {
					s.writeCh <- &Frame{Type: FRAME_TCP_CLOSE, StreamID: sid}
					break
				}
			}
			s.tcpStreams.Delete(sid) // #7
		}(f.StreamID, remoteConn)
		return nil

	case FRAME_TCP_DATA:
		// #7: sync.Map – lock-free lookup on hot path
		v, ok := s.tcpStreams.Load(f.StreamID)
		if !ok {
			return fmt.Errorf("no TCP stream %d for data", f.StreamID)
		}
		rc := v.(net.Conn)
		if len(f.Payload) > 0 {
			if _, err := rc.Write(f.Payload); err != nil {
				rc.Close()
				s.tcpStreams.Delete(f.StreamID)
			}
		}
		return nil

	case FRAME_TCP_CLOSE:
		// #7: sync.Map
		v, ok := s.tcpStreams.LoadAndDelete(f.StreamID)
		if ok {
			v.(net.Conn).Close()
		}
		return nil

	case FRAME_UDP_DATA:
		forwardID := f.ForwardID
		streamID := f.StreamID

		// #8: Split locking – read lock first to check, only write-lock if we need to dial
		s.mu.RLock()
		cfg, ok := s.forwards[forwardID]
		if !ok {
			s.mu.RUnlock()
			return fmt.Errorf("unknown forward ID %d for UDP_DATA", forwardID)
		}
		if cfg.proto != "udp" {
			s.mu.RUnlock()
			return fmt.Errorf("forward ID %d is not UDP", forwardID)
		}
		perFwd := s.udpSockets[forwardID]
		var udpConn *net.UDPConn
		if perFwd != nil {
			udpConn = perFwd[streamID]
		}
		s.mu.RUnlock()

		if udpConn == nil {
			// #8: Dial outside the lock
			remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(cfg.remotePort)}
			var err error
			udpConn, err = net.DialUDP("udp", nil, remote)
			if err != nil {
				return fmt.Errorf("dial udp remote %s: %w", remote, err)
			}

			// Now lock to insert
			s.mu.Lock()
			if s.udpSockets[forwardID] == nil {
				s.udpSockets[forwardID] = make(map[uint32]*net.UDPConn)
			}
			// Double-check: another goroutine may have created it
			if existing, ok := s.udpSockets[forwardID][streamID]; ok {
				s.mu.Unlock()
				udpConn.Close() // discard our duplicate
				udpConn = existing
			} else {
				s.udpSockets[forwardID][streamID] = udpConn
				s.mu.Unlock()

				// start read loop for data coming back from the remote service
				s.wg.Add(1)
				go func(fid uint16, sid uint32, conn *net.UDPConn) {
					defer s.wg.Done()
					bp := getBuf64K() // #1: pooled buffer
					buf := *bp
					defer putBuf64K(bp)
					for {
						n, _, err := conn.ReadFromUDP(buf)
						if err != nil {
							if ne, ok := err.(net.Error); ok && ne.Temporary() {
								continue
							}
							return
						}
						payload := make([]byte, n)
						copy(payload, buf[:n])
						s.writeCh <- &Frame{
							Type:      FRAME_UDP_DATA_BACK,
							ForwardID: fid,
							StreamID:  sid,
							Length:    uint32(n),
							Payload:   payload,
						}
					}
				}(forwardID, streamID, udpConn)
			}
		}

		// forward payload to remote service
		if len(f.Payload) > 0 {
			if _, err := udpConn.Write(f.Payload); err != nil {
				log.Printf("udp write error (fid %d, sid %d): %v", forwardID, streamID, err)
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown frame type %d", f.Type)
	}
}

/* -------------------------------------------------------------------------
CLIENT side – state structures
---------------------------------------------------------------------- */

type clientState struct {
	conn        net.Conn
	writeCh     chan *Frame
	forwards    map[uint16]forwardConfig
	tcpConns    sync.Map                          // streamID (uint32) → net.Conn
	udpForwards map[uint16]*udpForwarder
	wg          sync.WaitGroup
	lastPong    atomic.Int64                      // #11
	done        chan struct{}
}

type udpForwarder struct {
	listener    *net.UDPConn
	mu          sync.RWMutex
	srcToStream map[string]uint32
	streamToSrc map[uint32]*net.UDPAddr
}

/* -------------------------------------------------------------------------
GLOBAL stream ID generator
---------------------------------------------------------------------- */

var globalStreamID uint32

/* -------------------------------------------------------------------------
CLIENT entry point
---------------------------------------------------------------------- */

func runClient(serverAddr, token string, tcpMaps, udpMaps portMappingList) {
	c, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("cannot connect to %s: %v", serverAddr, err)
	}
	defer c.Close()
	setNoDelay(c) // #5
	log.Printf("connected to %s", serverAddr)

	state := &clientState{
		conn:        c,
		writeCh:     make(chan *Frame, 1024),
		forwards:    make(map[uint16]forwardConfig),
		udpForwards: make(map[uint16]*udpForwarder),
		done:        make(chan struct{}),
	}
	state.lastPong.Store(time.Now().Unix())

	// #10 FIX: writer goroutine – tracked separately so we can close writeCh
	// before wg.Wait() on the main goroutines.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for f := range state.writeCh {
			if err := writeFrame(state.conn, f); err != nil {
				log.Printf("tunnel write error: %v", err)
				return
			}
		}
	}()

	/* ------------------ authentication ------------------ */
	state.writeCh <- &Frame{
		Type:    FRAME_AUTH,
		Length:  uint32(len(token)),
		Payload: []byte(token),
	}
	resp, err := readFrame(state.conn)
	if err != nil {
		log.Fatalf("failed to read auth response: %v", err)
	}
	if resp.Type != FRAME_AUTH_RESP || string(resp.Payload) != "OK" {
		log.Fatalf("authentication failed: %s", string(resp.Payload))
	}
	log.Printf("authentication succeeded")

	/* ------------------ send forward configurations ------------------ */
	var forwardID uint16 = 1

	for _, m := range tcpMaps {
		cfg := forwardConfig{proto: "tcp", remotePort: m.remote}
		state.forwards[forwardID] = cfg

		pl := []byte{PROTO_TCP, 0, 0}
		binary.BigEndian.PutUint16(pl[1:], m.remote)

		state.writeCh <- &Frame{
			Type:      FRAME_CONFIG,
			ForwardID: forwardID,
			Length:    uint32(len(pl)),
			Payload:   pl,
		}
		startTCPListener(state, forwardID, m.local, m.remote)
		forwardID++
	}

	for _, m := range udpMaps {
		cfg := forwardConfig{proto: "udp", remotePort: m.remote}
		state.forwards[forwardID] = cfg

		pl := []byte{PROTO_UDP, 0, 0}
		binary.BigEndian.PutUint16(pl[1:], m.remote)

		state.writeCh <- &Frame{
			Type:      FRAME_CONFIG,
			ForwardID: forwardID,
			Length:    uint32(len(pl)),
			Payload:   pl,
		}
		startUDPForward(state, forwardID, m.local, m.remote)
		forwardID++
	}

	// #11: heartbeat – client responds to PINGs with PONGs, and monitors for timeout
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if time.Since(time.Unix(state.lastPong.Load(), 0)) > pingTimeout {
					log.Printf("server timed out (no ping received)")
					state.conn.Close()
					return
				}
			case <-state.done:
				return
			}
		}
	}()

	/* ------------------ receive frames from the tunnel ------------------ */
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		for {
			f, err := readFrame(state.conn)
			if err != nil {
				if err != io.EOF {
					log.Printf("tunnel read error: %v", err)
				}
				return
			}
			switch f.Type {

			// #11: keepalive
			case FRAME_PING:
				select {
				case state.writeCh <- &Frame{Type: FRAME_PONG}:
				default:
				}
				state.lastPong.Store(time.Now().Unix()) // received ping = server is alive

			case FRAME_PONG:
				state.lastPong.Store(time.Now().Unix())

			case FRAME_TCP_DATA:
				if v, ok := state.tcpConns.Load(f.StreamID); ok {
					c := v.(net.Conn)
					if len(f.Payload) > 0 {
						if _, err := c.Write(f.Payload); err != nil {
							c.Close()
							state.tcpConns.Delete(f.StreamID)
						}
					}
				}
			case FRAME_TCP_CLOSE:
				if v, ok := state.tcpConns.LoadAndDelete(f.StreamID); ok {
					v.(net.Conn).Close()
				}
			case FRAME_UDP_DATA_BACK:
				if u, ok := state.udpForwards[f.ForwardID]; ok {
					u.mu.RLock()
					dst := u.streamToSrc[f.StreamID]
					u.mu.RUnlock()
					if dst != nil {
						if _, err := u.listener.WriteToUDP(f.Payload, dst); err != nil {
							log.Printf("udp back write error (forwardID %d, stream %d): %v", f.ForwardID, f.StreamID, err)
						}
					} else {
						log.Printf("udp back for forwardID %d, stream %d but no source known", f.ForwardID, f.StreamID)
					}
				} else {
					log.Printf("udp back for unknown forwardID %d", f.ForwardID)
				}
			default:
				log.Printf("unexpected frame type %d on client side", f.Type)
			}
		}
	}()

	// #10 FIX: Wait for reader/listeners to finish, then close the write channel,
	// then wait for the writer goroutine to drain and exit.
	state.wg.Wait()
	close(state.done)
	close(state.writeCh)
	<-writerDone
}

/* -------------------------------------------------------------------------
Helper: start a TCP listener for a forward (client side)
---------------------------------------------------------------------- */

func startTCPListener(st *clientState, fwdID uint16, localPort, remotePort uint16) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		log.Fatalf("cannot listen on local TCP %d: %v", localPort, err)
	}
	log.Printf("TCP forward: 0.0.0.0:%d → server:%d (forwardID %d)", localPort, remotePort, fwdID)

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		defer ln.Close()
		for {
			locConn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}
			setNoDelay(locConn) // #5
			sid := atomic.AddUint32(&globalStreamID, 1)
			st.tcpConns.Store(sid, locConn)

			st.writeCh <- &Frame{
				Type:      FRAME_TCP_CONNECT,
				ForwardID: fwdID,
				StreamID:  sid,
			}

			// pump local → tunnel
			st.wg.Add(1)
			go func(sid uint32, lc net.Conn) {
				defer st.wg.Done()
				defer lc.Close()
				bp := getBuf16K() // #1: pooled buffer
				buf := *bp
				defer putBuf16K(bp)
				for {
					n, err := lc.Read(buf)
					if n > 0 {
						data := make([]byte, n)
						copy(data, buf[:n])
						st.writeCh <- &Frame{
							Type:     FRAME_TCP_DATA,
							StreamID: sid,
							Length:   uint32(n),
							Payload:  data,
						}
					}
					if err != nil {
						st.writeCh <- &Frame{
							Type:     FRAME_TCP_CLOSE,
							StreamID: sid,
						}
						st.tcpConns.Delete(sid)
						return
					}
				}
			}(sid, locConn)
		}
	}()
}

/* -------------------------------------------------------------------------
Helper: start a UDP forward (client side) – binds to 0.0.0.0
---------------------------------------------------------------------- */

func startUDPForward(st *clientState, fwdID uint16, localPort, remotePort uint16) {
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(localPort)})
	if err != nil {
		log.Fatalf("cannot listen UDP %d: %v", localPort, err)
	}
	u := &udpForwarder{
		listener:    udpListener,
		srcToStream: make(map[string]uint32),
		streamToSrc: make(map[uint32]*net.UDPAddr),
	}
	if st.udpForwards == nil {
		st.udpForwards = make(map[uint16]*udpForwarder)
	}
	st.udpForwards[fwdID] = u

	log.Printf("UDP forward: 0.0.0.0:%d → server:%d (forwardID %d)", localPort, remotePort, fwdID)

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		defer udpListener.Close()
		bp := getBuf64K() // #1: pooled buffer
		buf := *bp
		defer putBuf64K(bp)
		for {
			n, src, err := udpListener.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			srcKey := src.String()
			var sid uint32
			u.mu.RLock()
			sid, ok := u.srcToStream[srcKey]
			u.mu.RUnlock()
			if !ok {
				sid = atomic.AddUint32(&globalStreamID, 1)
				u.mu.Lock()
				u.srcToStream[srcKey] = sid
				u.streamToSrc[sid] = src
				u.mu.Unlock()
			}

			payload := make([]byte, n)
			copy(payload, buf[:n])

			st.writeCh <- &Frame{
				Type:      FRAME_UDP_DATA,
				ForwardID: fwdID,
				StreamID:  sid,
				Length:    uint32(n),
				Payload:   payload,
			}
		}
	}()
}

/* -------------------------------------------------------------------------
main()
---------------------------------------------------------------------- */

func main() {
	mode := flag.String("mode", "", "server or client")
	srvPort := flag.Int("port", 0, "listen port (server mode)")
	token := flag.String("token", "", "shared secret token")
	clientHost := flag.String("host", "", "server address (client mode, e.g. example.com:8081)")

	var tcpForwards portMappingList
	var udpForwards portMappingList
	flag.Var(&tcpForwards, "forward", "TCP forward: localPort,remotePort (repeatable)")
	flag.Var(&udpForwards, "forwardudp", "UDP forward: localPort,remotePort (repeatable)")

	flag.Parse()

	if *mode != "server" && *mode != "client" {
		fmt.Fprintf(os.Stderr, "must specify -mode server|client\n")
		flag.Usage()
		os.Exit(1)
	}
	if *token == "" {
		fmt.Fprintf(os.Stderr, "-token is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if *mode == "server" {
		if *srvPort == 0 {
			fmt.Fprintf(os.Stderr, "-port is required for server mode\n")
			flag.Usage()
			os.Exit(1)
		}
		runServer(*srvPort, *token)
	} else {
		if *clientHost == "" {
			fmt.Fprintf(os.Stderr, "-host is required for client mode\n")
			flag.Usage()
			os.Exit(1)
		}
		runClient(*clientHost, *token, tcpForwards, udpForwards)
	}
}
