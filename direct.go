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
// “0.0.0.0:port”, i.e. they accept connections from every network interface.

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

	PROTO_TCP = 0
	PROTO_UDP = 1

	headerSize = 12 // 1+1+2+4+4 bytes
)

type Frame struct {
	Type      uint8
	ForwardID uint16 // 0 when the frame does not need a forward‑ID
	StreamID  uint32 // 0 when the frame does not need a stream‑ID
	Length    uint32 // length of Payload
	Payload   []byte // optional
}

// write a complete frame to w
func writeFrame(w io.Writer, f *Frame) error {
	hdr := make([]byte, headerSize)
	hdr[0] = f.Type
	// hdr[1] is reserved (0)
	binary.BigEndian.PutUint16(hdr[2:4], f.ForwardID)
	binary.BigEndian.PutUint32(hdr[4:8], f.StreamID)
	binary.BigEndian.PutUint32(hdr[8:12], f.Length)

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if f.Length > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// read a complete frame from r
func readFrame(r io.Reader) (*Frame, error) {
	hdr := make([]byte, headerSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
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

// flag.Value implementation – “local,remote” (repeatable)
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
	conn        net.Conn
	token       string
	writeCh     chan *Frame
	forwards    map[uint16]forwardConfig               // forwardID → config
	tcpStreams  map[uint32]net.Conn                    // streamID → remote TCP conn
	udpSockets  map[uint16]map[uint32]*net.UDPConn      // forwardID → streamID → UDP conn
	mu          sync.Mutex
	wg          sync.WaitGroup
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
		tcpStreams: make(map[uint32]net.Conn),
		udpSockets: make(map[uint16]map[uint32]*net.UDPConn),
	}
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

	/* ------------------ authentication ------------------ */
	auth, err := readFrame(sess.conn)
	if err != nil {
		log.Printf("auth read error from %s: %v", sess.conn.RemoteAddr(), err)
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	if auth.Type != FRAME_AUTH {
		log.Printf("expected AUTH frame, got %d", auth.Type)
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	if string(auth.Payload) != sess.token {
		sess.writeCh <- &Frame{
			Type:   FRAME_AUTH_RESP,
			Length: uint32(len("FAIL")),
			Payload: []byte("FAIL"),
		}
		close(sess.writeCh)
		sess.wg.Wait()
		return
	}
	sess.writeCh <- &Frame{
		Type:   FRAME_AUTH_RESP,
		Length: uint32(len("OK")),
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
	close(sess.writeCh)
	sess.cleanup()
	sess.wg.Wait()
	log.Printf("session %s closed", sess.conn.RemoteAddr())
}

/* ---------------------------------------------------------------------
Clean‑up all active streams / sockets
--------------------------------------------------------------------- */

func (s *clientSession) cleanup() {
	s.mu.Lock()
	for _, c := range s.tcpStreams {
		c.Close()
	}
	for _, perForward := range s.udpSockets {
		for _, conn := range perForward {
			conn.Close()
		}
	}
	s.tcpStreams = nil
	s.udpSockets = nil
	s.mu.Unlock()
}

/* ---------------------------------------------------------------------
Frame dispatcher (server side)
--------------------------------------------------------------------- */

func (s *clientSession) handleFrame(f *Frame) error {
	switch f.Type {

	case FRAME_CONFIG: // client tells us which remote port & protocol this forwardID uses
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
		// pre‑allocate map for UDP sockets (lazy, but harmless for TCP)
		if cfg.proto == "udp" {
			if _, ok := s.udpSockets[f.ForwardID]; !ok {
				s.udpSockets[f.ForwardID] = make(map[uint32]*net.UDPConn)
			}
		}
		s.mu.Unlock()
		return nil

	case FRAME_TCP_CONNECT:
		s.mu.Lock()
		cfg, ok := s.forwards[f.ForwardID]
		s.mu.Unlock()
		if !ok {
			return fmt.Errorf("unknown forward ID %d for TCP_CONNECT", f.ForwardID)
		}
		if cfg.proto != "tcp" {
			return fmt.Errorf("forward ID %d is not TCP", f.ForwardID)
		}
		remote := fmt.Sprintf("127.0.0.1:%d", cfg.remotePort)
		remoteConn, err := net.Dial("tcp", remote)
		if err != nil {
			// tell client that the connection failed
			s.writeCh <- &Frame{Type: FRAME_TCP_CLOSE, StreamID: f.StreamID}
			return fmt.Errorf("dial %s: %w", remote, err)
		}

		s.mu.Lock()
		s.tcpStreams[f.StreamID] = remoteConn
		s.mu.Unlock()

		// pump data from remote → client
		s.wg.Add(1)
		go func(sid uint32, rc net.Conn) {
			defer s.wg.Done()
			defer rc.Close()
			buf := make([]byte, 16*1024)
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
					// remote closed or error – tell client
					s.writeCh <- &Frame{Type: FRAME_TCP_CLOSE, StreamID: sid}
					break
				}
			}
			// clean up map entry
			s.mu.Lock()
			delete(s.tcpStreams, sid)
			s.mu.Unlock()
		}(f.StreamID, remoteConn)
		return nil

	case FRAME_TCP_DATA:
		s.mu.Lock()
		rc, ok := s.tcpStreams[f.StreamID]
		s.mu.Unlock()
		if !ok {
			return fmt.Errorf("no TCP stream %d for data", f.StreamID)
		}
		if len(f.Payload) > 0 {
			if _, err := rc.Write(f.Payload); err != nil {
				rc.Close()
				s.mu.Lock()
				delete(s.tcpStreams, f.StreamID)
				s.mu.Unlock()
			}
		}
		return nil

	case FRAME_TCP_CLOSE:
		s.mu.Lock()
		rc, ok := s.tcpStreams[f.StreamID]
		if ok {
			rc.Close()
			delete(s.tcpStreams, f.StreamID)
		}
		s.mu.Unlock()
		return nil

	case FRAME_UDP_DATA:
		forwardID := f.ForwardID
		streamID := f.StreamID

		s.mu.Lock()
		cfg, ok := s.forwards[forwardID]
		if !ok {
			s.mu.Unlock()
			return fmt.Errorf("unknown forward ID %d for UDP_DATA", forwardID)
		}
		if cfg.proto != "udp" {
			s.mu.Unlock()
			return fmt.Errorf("forward ID %d is not UDP", forwardID)
		}
		// make sure map[streamID]*net.UDPConn exists
		if s.udpSockets[forwardID] == nil {
			s.udpSockets[forwardID] = make(map[uint32]*net.UDPConn)
		}
		udpConn, ok := s.udpSockets[forwardID][streamID]
		if !ok {
			remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(cfg.remotePort)}
			var err error
			udpConn, err = net.DialUDP("udp", nil, remote)
			if err != nil {
				s.mu.Unlock()
				return fmt.Errorf("dial udp remote %s: %w", remote, err)
			}
			s.udpSockets[forwardID][streamID] = udpConn

			// start a read loop for data coming back from the remote service
			s.wg.Add(1)
			go func(fid uint16, sid uint32, conn *net.UDPConn) {
				defer s.wg.Done()
				buf := make([]byte, 65535)
				for {
					n, _, err := conn.ReadFromUDP(buf)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Temporary() {
							continue
						}
						return // socket closed or fatal error
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
		s.mu.Unlock()

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
	forwards    map[uint16]forwardConfig          // forwardID → config (proto, remotePort)
	tcpConns    sync.Map                          // streamID (uint32) → net.Conn (local TCP side)
	udpForwards map[uint16]*udpForwarder          // forwardID → UDP forwarder (listener + src tracking)
	wg          sync.WaitGroup
}

// udpForwarder represents a single UDP forward on the client:
// * a UDP socket listening on all interfaces (0.0.0.0)
// * the most‑recent source address that sent us a packet (so we can reply)
type udpForwarder struct {
	listener     *net.UDPConn
	mu           sync.RWMutex // protects the maps below
	srcToStream  map[string]uint32
	streamToSrc  map[uint32]*net.UDPAddr
}

/* -------------------------------------------------------------------------
GLOBAL stream ID generator (used for both TCP and UDP)
---------------------------------------------------------------------- */

var globalStreamID uint32 // monotonically increasing stream ID for both TCP and UDP

/* -------------------------------------------------------------------------
CLIENT entry point
---------------------------------------------------------------------- */

func runClient(serverAddr, token string, tcpMaps, udpMaps portMappingList) {
	c, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("cannot connect to %s: %v", serverAddr, err)
	}
	defer c.Close()
	log.Printf("connected to %s", serverAddr)

	state := &clientState{
		conn:        c,
		writeCh:     make(chan *Frame, 1024),
		forwards:    make(map[uint16]forwardConfig),
		udpForwards: make(map[uint16]*udpForwarder),
	}

	// writer goroutine (single‑threaded writes to the tunnel)
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		for f := range state.writeCh {
			if err := writeFrame(state.conn, f); err != nil {
				log.Printf("tunnel write error: %v", err)
				return
			}
		}
	}()

	/* ------------------ authentication ------------------ */
	state.writeCh <- &Frame{
		Type:   FRAME_AUTH,
		Length: uint32(len(token)),
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

	// ---- TCP forwards --------------------------------------------------
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

	// ---- UDP forwards --------------------------------------------------
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
				if v, ok := state.tcpConns.Load(f.StreamID); ok {
					c := v.(net.Conn)
					c.Close()
					state.tcpConns.Delete(f.StreamID)
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

	// Wait for everything (listeners, tunnel writer/reader) to finish.
	state.wg.Wait()
	close(state.writeCh)
}

/* -------------------------------------------------------------------------
Helper: start a TCP listener for a forward (client side)
---------------------------------------------------------------------- */

func startTCPListener(st *clientState, fwdID uint16, localPort, remotePort uint16) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort)) // 0.0.0.0:port
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
			sid := atomic.AddUint32(&globalStreamID, 1)
			st.tcpConns.Store(sid, locConn)

			// tell the server to open a matching connection
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
				buf := make([]byte, 16*1024)
				for {
					n, err := lc.Read(buf)
					if n > 0 {
						data := make([]byte, n)
						copy(data, buf[:n])
						st.writeCh <- &Frame{
							Type:      FRAME_TCP_DATA,
							StreamID:  sid,
							Length:    uint32(n),
							Payload:   data,
						}
					}
					if err != nil {
						// signal close to the server
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
	// Bind the listener on all interfaces (0.0.0.0)
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
		buf := make([]byte, 65535)
		for {
			n, src, err := udpListener.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				// listener closed; exit goroutine
				return
			}

			// Resolve / allocate a stream ID for this source address
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
