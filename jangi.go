package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xtaci/smux"
)

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host (vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
	forward := flag.String("forward", "", "Local port to forward to (vpn mode)")
	forwardudp := flag.String("forwardudp", "", "Local UDP port to forward to (vpn mode) — enable UDP forwarding when set")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	// signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("signal: shutdown requested, cancelling context...")
		cancel()
	}()

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("relay mode requires -port")
		}
		runRelay(ctx, wg, *port)
	case "vpn":
		if *host == "" || *port == "" || *forward == "" {
			log.Fatal("vpn mode requires -host, -port, and -forward")
		}
		runVPN(ctx, wg, *host, *port, *forward, *forwardudp)
	default:
		log.Fatal("Invalid mode, use relay or vpn")
	}

	// wait for background goroutines to finish
	wg.Wait()
	log.Println("shutdown complete")
}

// generateSelfSignedCert creates a new self‑signed TLS certificate (RSA 2048, valid for 1 year)
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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
			CommonName: "relay",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// PEM encode the certificate and private key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func tlsServerConfig() (*tls.Config, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate self‑signed certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, // TLS 1.2
			tls.TLS_CHACHA20_POLY1305_SHA256,               // TLS 1.3
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
	}, nil
}

func tlsClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // self‑signed, no need to verify
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// ---- Relay ----

func runRelay(ctx context.Context, wg *sync.WaitGroup, port string) {
	tlsConfig, err := tlsServerConfig()
	if err != nil {
		log.Fatalf("relay: failed to create TLS config: %v", err)
	}

	tcpListener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("relay: failed to listen on port %s: %v", port, err)
	}
	listener := tls.NewListener(tcpListener, tlsConfig)
	log.Printf("relay: listening on port %s for TLS‑secured Control Channel connections", port)

	acceptWg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer tcpListener.Close()
		for {
			connChan := make(chan net.Conn)
			errChan := make(chan error)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					errChan <- err
					return
				}
				connChan <- c
			}()

			select {
			case <-ctx.Done():
				log.Println("relay: context cancelled, stop accepting control connections")
				return
			case err := <-errChan:
				log.Printf("relay: accept error: %v", err)
				// small sleep to avoid tight loop
				time.Sleep(100 * time.Millisecond)
				continue
			case conn := <-connChan:
				acceptWg.Add(1)
				go func(c net.Conn) {
					defer acceptWg.Done()
					log.Printf("relay: accepted TLS Control Channel connection from %s", c.RemoteAddr())
					handleControlChannel(ctx, c)
				}(conn)
			}
		}
	}()

	// wait for accept loop to finish (ctx cancellation)
	acceptWg.Wait()
	log.Println("relay: stopped accepting control connections")
}

type udpSessionMeta struct {
	expectedCSID  uint32
	expectedAuth  []byte // 16 bytes
	vpnPeer       net.Addr
	vpnPeerLock   sync.RWMutex
	clientLock    sync.RWMutex
	addrToCSID    map[string]uint32
	csidToAddr    map[uint32]net.Addr
	nextRandomMtx sync.Mutex
}

func handleControlChannel(ctx context.Context, controlChannelConn net.Conn) {
	defer controlChannelConn.Close()

	reader := bufio.NewReader(controlChannelConn)

	// Read TCP forward port (old behavior)
	tcpLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("relay: failed to read forward TCP port from VPN client via Control Channel: %v", err)
		return
	}
	forwardPort := strings.TrimSpace(tcpLine)
	log.Printf("relay: TCP forwarding port received via Control Channel: %s", forwardPort)

	// Read UDP forward port (new: VPN sends empty line if none)
	udpLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("relay: failed to read forward UDP port from VPN client via Control Channel: %v", err)
		return
	}
	forwardUDP := strings.TrimSpace(udpLine)
	if forwardUDP != "" {
		log.Printf("relay: UDP forwarding port received via Control Channel: %s", forwardUDP)
	} else {
		log.Printf("relay: no UDP forwarding requested for this Control Channel")
	}

	var meta *udpSessionMeta
	if forwardUDP != "" {
		// Read CSID line and auth hex (from VPN)
		csidLine, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("relay: failed to read UDP session id from VPN via Control Channel: %v", err)
			return
		}
		authLine, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("relay: failed to read UDP auth from VPN via Control Channel: %v", err)
			return
		}
		csidLine = strings.TrimSpace(csidLine)
		authLine = strings.TrimSpace(authLine)
		csid64, err := strconv.ParseUint(csidLine, 10, 32)
		if err != nil {
			log.Printf("relay: invalid csid received: %v", err)
			return
		}
		authBytes, err := hex.DecodeString(authLine)
		if err != nil || len(authBytes) != 16 {
			log.Printf("relay: invalid udp auth token: %v", err)
			return
		}
		meta = &udpSessionMeta{
			expectedCSID: uint32(csid64),
			expectedAuth: authBytes,
			addrToCSID:   make(map[string]uint32),
			csidToAddr:   make(map[uint32]net.Addr),
		}
	}

	config := smux.DefaultConfig()
	config.MaxReceiveBuffer = 4194304
	config.KeepAliveTimeout = 30 * time.Second

	session, err := smux.Server(controlChannelConn, config)
	if err != nil {
		log.Printf("relay: failed to create smux server on Control Channel: %v", err)
		return
	}
	defer session.Close()
	log.Printf("relay: smux session established on Control Channel")

	// Start UDP forwarding if requested
	var udpPacketConn net.PacketConn
	var udpDone chan struct{}
	if forwardUDP != "" {
		pc, err := net.ListenPacket("udp", ":"+forwardUDP)
		if err != nil {
			log.Printf("relay: failed to listen on UDP %s: %v", forwardUDP, err)
			// continue only with TCP forwarding
		} else {
			udpPacketConn = pc
			udpDone = make(chan struct{})
			go func() {
				relayUDPHandler(ctx, pc, meta)
				close(udpDone)
			}()
			log.Printf("relay: listening on UDP :%s for Forwarded UDP clients", forwardUDP)
		}
	}

	tcpListener, err := net.Listen("tcp", ":"+forwardPort)
	if err != nil {
		log.Printf("relay: failed to listen on %s: %v", forwardPort, err)
		if udpPacketConn != nil {
			udpPacketConn.Close()
			<-udpDone
		}
		return
	}
	defer tcpListener.Close()
	log.Printf("relay: listening on :%s for Forwarded TCP Connections", forwardPort)

	// Accept forwarded TCP connections and create streams
	acceptLoop:
	for {
		select {
		case <-ctx.Done():
			log.Println("relay: control handler context cancelled, closing listeners")
			break acceptLoop
		default:
		}

		// Use concrete *net.TCPListener to set deadline if possible
		if tl, ok := tcpListener.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
		}
		forwardedConn, err := tcpListener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("relay: failed to accept Forwarded Connection: %v", err)
			break
		}
		log.Printf("relay: accepted Forwarded Connection from %s", forwardedConn.RemoteAddr())

		stream, err := session.OpenStream()
		if err != nil {
			log.Printf("relay: failed to open smux stream on Control Channel: %v", err)
			forwardedConn.Close()
			continue
		}
		log.Printf("relay: created new stream on Control Channel for Forwarded Connection %s", forwardedConn.RemoteAddr())
		go forwardConnection(forwardedConn, stream)
	}

	if udpPacketConn != nil {
		udpPacketConn.Close()
		<-udpDone
	}
	log.Println("relay: control channel handler exiting")
}

// relayUDPHandler handles plain UDP forwarding for one control session
func relayUDPHandler(ctx context.Context, pc net.PacketConn, meta *udpSessionMeta) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			log.Println("relay: udp handler context cancelled")
			return
		default:
		}

		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("relay: UDP listener closed or error: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		data := buf[:n]

		// If packet from vpn peer, it can be register (0x01) or data (0x02)
		meta.vpnPeerLock.RLock()
		vpnPeer := meta.vpnPeer
		meta.vpnPeerLock.RUnlock()

		// Process register: 0x01 | csid(4) | auth(16)
		if len(data) >= 1 && data[0] == 0x01 {
			if len(data) < 1+4+16 {
				log.Printf("relay: malformed register packet from %s", addr.String())
				continue
			}
			csid := binary.BigEndian.Uint32(data[1 : 1+4])
			auth := data[1+4 : 1+4+16]
			if csid != meta.expectedCSID || !equalBytes(auth, meta.expectedAuth) {
				log.Printf("relay: UDP register from %s failed auth (csid mismatch or auth mismatch)", addr.String())
				continue
			}
			// set vpn peer for this UDP forward socket
			meta.vpnPeerLock.Lock()
			meta.vpnPeer = addr
			meta.vpnPeerLock.Unlock()
			log.Printf("relay: registered VPN UDP peer %s for csid=%d", addr.String(), csid)
			continue
		}

		// Packet from vpn peer: 0x02 | csid(4) | clientSessionID(4) | payload...
		if vpnPeer != nil && addr.String() == vpnPeer.String() {
			if data[0] != 0x02 {
				log.Printf("relay: unknown packet type %02x from vpn peer", data[0])
				continue
			}
			if len(data) < 1+4+4 {
				log.Printf("relay: malformed data packet from vpn peer (too short)")
				continue
			}
			csid := binary.BigEndian.Uint32(data[1:5])
			if csid != meta.expectedCSID {
				log.Printf("relay: csid mismatch in packet from vpn peer: got %d expected %d", csid, meta.expectedCSID)
				continue
			}
			clientSessionID := binary.BigEndian.Uint32(data[5:9])
			payload := data[9:n]

			// Lookup clientSessionID -> external client addr
			meta.clientLock.RLock()
			dst, ok := meta.csidToAddr[clientSessionID]
			meta.clientLock.RUnlock()
			if !ok {
				log.Printf("relay: unknown clientSessionID %d from vpn peer, dropping", clientSessionID)
				continue
			}
			_, err = pc.WriteTo(payload, dst)
			if err != nil {
				log.Printf("relay: failed to forward UDP payload to external client %s: %v", dst.String(), err)
			}
			continue
		}

		// Packet from external client: we need to map addr -> clientSessionID (create if new) and forward to vpn peer
		meta.clientLock.Lock()
		clientAddrStr := addr.String()
		csid := meta.expectedCSID
		clientSID, exists := meta.addrToCSID[clientAddrStr]
		if !exists {
			// allocate random uint32 that is non-zero and not colliding
			clientSID = randomNonZeroUint32(func(v uint32) bool {
				_, exists2 := meta.csidToAddr[v]
				return exists2
			})
			meta.addrToCSID[clientAddrStr] = clientSID
			meta.csidToAddr[clientSID] = addr
			log.Printf("relay: new external UDP client %s assigned clientSessionID %d", clientAddrStr, clientSID)
		}
		meta.clientLock.Unlock()

		// Ensure vpnPeer present
		meta.vpnPeerLock.RLock()
		currVpn := meta.vpnPeer
		meta.vpnPeerLock.RUnlock()
		if currVpn == nil {
			log.Printf("relay: received UDP from %s but no VPN peer registered yet for this UDP forward port; dropping", addr.String())
			continue
		}

		// Build frame: 0x02 | csid(4) | clientSessionID(4) | payload
		out := make([]byte, 1+4+4+len(data))
		out[0] = 0x02
		binary.BigEndian.PutUint32(out[1:5], csid)
		binary.BigEndian.PutUint32(out[5:9], clientSID)
		copy(out[9:], data)
		_, err = pc.WriteTo(out, currVpn)
		if err != nil {
			log.Printf("relay: failed to forward UDP frame to vpn peer %s: %v", currVpn.String(), err)
		}
	}
}

// ---- VPN ----

func runVPN(ctx context.Context, wg *sync.WaitGroup, relayHost, relayPort, forwardPort, forwardUDP string) {
	tlsConfig := tlsClientConfig()

	for {
		select {
		case <-ctx.Done():
			log.Println("vpn: context cancelled, exiting run loop")
			return
		default:
		}

		log.Printf("vpn: establishing TLS Control Channel to relay %s:%s", relayHost, relayPort)

		controlChannelConn, err := tls.Dial("tcp", net.JoinHostPort(relayHost, relayPort), tlsConfig)
		if err != nil {
			log.Printf("vpn: failed to establish TLS Control Channel to relay %s:%s: %v", relayHost, relayPort, err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("vpn: TLS Control Channel established to relay %s:%s", relayHost, relayPort)

		// If UDP forward requested, create csid and auth token
		var csid uint32
		var authToken []byte
		if forwardUDP != "" {
			csid = randomUint32()
			authToken = make([]byte, 16)
			_, err := rand.Read(authToken)
			if err != nil {
				log.Printf("vpn: failed to generate udp auth token: %v", err)
				controlChannelConn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
			// send TCP forward port and UDP forward port and csid and auth hex
			_, err = fmt.Fprintf(controlChannelConn, "%s\n%s\n%d\n%s\n", forwardPort, forwardUDP, csid, hex.EncodeToString(authToken))
			if err != nil {
				log.Printf("vpn: failed to send forward ports to relay via Control Channel: %v", err)
				controlChannelConn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
		} else {
			// send only tcp forward and empty udp line (two lines)
			_, err = fmt.Fprintf(controlChannelConn, "%s\n\n", forwardPort)
			if err != nil {
				log.Printf("vpn: failed to send forward ports to relay via Control Channel: %v", err)
				controlChannelConn.Close()
				time.Sleep(5 * time.Second)
				continue
			}
		}

		config := smux.DefaultConfig()
		config.MaxReceiveBuffer = 4194304
		config.KeepAliveTimeout = 30 * time.Second

		session, err := smux.Client(controlChannelConn, config)
		if err != nil {
			log.Printf("vpn: failed to create smux client on Control Channel: %v", err)
			controlChannelConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		// If UDP forward requested, establish plain UDP connection to relay's UDP port and register
		var udpConn net.PacketConn
		var udpRemote net.Addr
		var udpDone chan struct{}
		if forwardUDP != "" {
			raddr := net.JoinHostPort(relayHost, forwardUDP)
			pc, err := net.ListenPacket("udp", ":0") // ephemeral local source port
			if err != nil {
				log.Printf("vpn: failed to open local UDP socket for forwarding: %v", err)
			} else {
				udpConn = pc
				udpRemoteAddr, err := net.ResolveUDPAddr("udp", raddr)
				if err != nil {
					log.Printf("vpn: failed to resolve relay UDP addr %s: %v", raddr, err)
					udpConn.Close()
					udpConn = nil
				} else {
					udpRemote = udpRemoteAddr
					// Send registration packet: 0x01 | csid(4) | auth(16)
					reg := make([]byte, 1+4+16)
					reg[0] = 0x01
					binary.BigEndian.PutUint32(reg[1:5], csid)
					copy(reg[5:], authToken)
					_, err = udpConn.WriteTo(reg, udpRemote)
					if err != nil {
						log.Printf("vpn: failed to send UDP registration to relay %s: %v", raddr, err)
						udpConn.Close()
						udpConn = nil
					} else {
						log.Printf("vpn: sent UDP registration to relay %s from local %s (csid=%d)", raddr, udpConn.LocalAddr().String(), csid)
						udpDone = make(chan struct{})
						wg.Add(1)
						go func() {
							defer wg.Done()
							vpnUDPHandler(ctx, udpConn, udpRemote, csid, forwardPort)
							close(udpDone)
						}()
					}
				}
			}
		}

		log.Printf("vpn: smux session established on Control Channel, handling streams")

		// Start handling streams (TCP forwarding) — run in goroutine to allow ctx cancellation
		streamErr := make(chan error, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			streamErr <- handleVPNStreamsWithCtx(ctx, session, forwardPort)
		}()

		// wait until streams exit or ctx cancelled
		select {
		case <-ctx.Done():
			log.Println("vpn: context cancelled, closing session")
		case err := <-streamErr:
			if err != nil {
				log.Printf("vpn: stream handler exited with error: %v", err)
			} else {
				log.Printf("vpn: stream handler exited cleanly")
			}
		}

		// teardown
		session.Close()
		controlChannelConn.Close()
		if udpConn != nil {
			udpConn.Close()
			<-udpDone
		}
		// if ctx isn't done, attempt reconnect after a pause
		select {
		case <-ctx.Done():
			log.Println("vpn: exiting run loop due to context cancellation")
			return
		default:
			log.Println("vpn: Control Channel closed, reconnecting in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
}

func handleVPNStreamsWithCtx(ctx context.Context, session *smux.Session, forwardPort string) error {
	for {
		// break if context cancelled
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// AcceptStream will block; rely on ctx and outer session.Close to unblock
		stream, err := session.AcceptStream()
		if err != nil {
			// If session is closed, AcceptStream returns an error; propagate it
			return fmt.Errorf("failed to accept stream from Control Channel: %v", err)
		}
		log.Printf("vpn: accepted new stream via Control Channel")
		go handleVPNStream(stream, forwardPort)
	}
}

func handleVPNStream(stream *smux.Stream, forwardPort string) {
	defer stream.Close()

	localConn, err := net.Dial("tcp", "127.0.0.1:"+forwardPort)
	if err != nil {
		log.Printf("vpn: failed to connect to localhost:%s: %v", forwardPort, err)
		return
	}
	defer localConn.Close()

	log.Printf("vpn: forwarding Control Channel stream to localhost:%s", forwardPort)
	forwardConnection(stream, localConn)
}

// vpnUDPHandler demultiplexes incoming frames from relay and forwards to local UDP service,
// and sends responses back to relay. It keeps per-client local UDP sockets keyed by clientSessionID.
func vpnUDPHandler(ctx context.Context, pc net.PacketConn, relayAddr net.Addr, csid uint32, localForwardPort string) {
	// Map clientSessionID -> localEntry
	type localEntry struct {
		conn       net.PacketConn
		lastActive time.Time
		stopCh     chan struct{}
	}
	localMap := make(map[uint32]*localEntry)
	var mu sync.Mutex

	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	// helper to create local connection (to localForwardPort) for a clientSessionID
	createLocalConn := func(clientSID uint32) (*localEntry, error) {
		mu.Lock()
		defer mu.Unlock()
		if e, ok := localMap[clientSID]; ok {
			e.lastActive = time.Now()
			return e, nil
		}
		localConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, err
		}
		le := &localEntry{
			conn:       localConn,
			lastActive: time.Now(),
			stopCh:     make(chan struct{}),
		}
		localMap[clientSID] = le

		// goroutine to read replies from local service and forward back to relay with framing
		go func(sid uint32, entry *localEntry) {
			buf := make([]byte, 65535)
			for {
				entry.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, _, err := entry.conn.ReadFrom(buf)
				if err != nil {
					select {
					case <-entry.stopCh:
						return
					default:
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						// timeout: continue
						continue
					}
					// other errors -> close
					log.Printf("vpn: localConn read error for clientSID %d: %v", sid, err)
					return
				}
				// Frame back: 0x02 | csid(4) | clientSessionID(4) | payload
				frame := make([]byte, 1+4+4+n)
				frame[0] = 0x02
				binary.BigEndian.PutUint32(frame[1:5], csid)
				binary.BigEndian.PutUint32(frame[5:9], sid)
				copy(frame[9:], buf[:n])
				_, err = pc.WriteTo(frame, relayAddr)
				if err != nil {
					log.Printf("vpn: failed to send UDP response frame to relay for clientSID %d: %v", sid, err)
				}
			}
		}(clientSID, le)

		return le, nil
	}

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			// cleanup local entries
			mu.Lock()
			for sid, e := range localMap {
				close(e.stopCh)
				e.conn.Close()
				delete(localMap, sid)
			}
			mu.Unlock()
			return
		case <-cleanupTicker.C:
			// cleanup stale entries (no activity for 2m)
			mu.Lock()
			for k, e := range localMap {
				if time.Since(e.lastActive) > 2*time.Minute {
					close(e.stopCh)
					e.conn.Close()
					delete(localMap, k)
				}
			}
			mu.Unlock()
		default:
		}

		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("vpn: UDP read error: %v", err)
			return
		}
		if addr.String() != relayAddr.String() {
			// ignore unexpected senders
			log.Printf("vpn: ignoring UDP packet from unexpected addr %s (expecting %s)", addr.String(), relayAddr.String())
			continue
		}
		if n == 0 {
			continue
		}
		data := buf[:n]
		if data[0] == 0x01 {
			// registration ack/refresh from relay (ignore)
			continue
		} else if data[0] == 0x02 {
			// framed data from relay => deliver to local forward service
			if len(data) < 1+4+4 {
				log.Printf("vpn: malformed UDP data from relay (too short)")
				continue
			}
			rCsid := binary.BigEndian.Uint32(data[1:5])
			if rCsid != csid {
				log.Printf("vpn: csid mismatch in UDP data from relay: got %d expected %d", rCsid, csid)
				continue
			}
			clientSID := binary.BigEndian.Uint32(data[5:9])
			payload := data[9:n]

			// send payload to local forward service, ensure localConn exists
			entry, err := createLocalConn(clientSID)
			if err != nil {
				log.Printf("vpn: failed to create local UDP conn for clientSID %d: %v", clientSID, err)
				continue
			}
			entry.lastActive = time.Now()
			localServiceAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
			portInt, _ := strconv.Atoi(localForwardPort)
			localServiceAddr.Port = portInt
			_, err = entry.conn.WriteTo(payload, localServiceAddr)
			if err != nil {
				log.Printf("vpn: failed to write payload to local service for clientSID %d: %v", clientSID, err)
			}
		} else {
			log.Printf("vpn: unknown UDP packet type %02x from relay", data[0])
			continue
		}
	}
}

// ---- common helpers ----

func forwardConnection(forwardedConn, stream net.Conn) {
	defer forwardedConn.Close()
	defer stream.Close()

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(stream, forwardedConn)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(forwardedConn, stream)
	}()

	<-done
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomUint32() uint32 {
	var b [4]byte
	_, err := rand.Read(b[:])
	if err != nil {
		// fallback
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func randomNonZeroUint32(collides func(uint32) bool) uint32 {
	for {
		v := randomUint32()
		if v == 0 {
			continue
		}
		if collides != nil && collides(v) {
			continue
		}
		return v
	}
}
