package main

import (
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

const (
	bufferSize        = 32 * 1024 // 32KB buffer
	keepAliveInterval = 10 * time.Second
	keepAliveTimeout  = 30 * time.Second
	reconnectDelay    = 2 * time.Second
	udpTimeout        = 90 * time.Second
	udpBufferSize     = 64 * 1024
	udpBatchSize      = 16
	healthCheckPeriod = 5 * time.Second
)

var (
	// Sync pool for buffers
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, bufferSize)
			return &buf
		},
	}

	// Sync pool for small read buffers (64 bytes for port reading)
	smallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64)
			return &buf
		},
	}

	// Sync pool for UDP buffers
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, udpBufferSize)
			return &buf
		},
	}
)

// RelaySession manages listeners and reuses sockets across reconnections
type RelaySession struct {
	session   *smux.Session
	listeners map[string]net.Listener
	udpConns  map[string]*net.UDPConn
	mu        sync.RWMutex
}

// UDPSession represents a UDP client session
type UDPSession struct {
	clientAddr *net.UDPAddr
	stream     *smux.Stream
	lastActive time.Time
	writeChan  chan []byte
	mu         sync.Mutex
}

// ForwardMapping represents a port forwarding configuration
type ForwardMapping struct {
	LocalPort  string
	RemotePort string
	IsUDP      bool
}

// RelayConnection represents a single relay server connection
type RelayConnection struct {
	host        string
	port        string
	session     *smux.Session
	conn        net.Conn
	healthy     atomic.Bool
	lastSuccess time.Time
	failures    atomic.Int32
	mu          sync.RWMutex
}

// RelayPool manages multiple relay connections
type RelayPool struct {
	relays   []*RelayConnection
	current  atomic.Uint32
	token    string
	mappings []ForwardMapping
	mu       sync.RWMutex
}

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host(s), comma-separated for multiple (used in vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
	forward := flag.String("forward", "", "TCP port mappings: LOCAL:REMOTE,LOCAL:REMOTE (used in vpn mode)")
	forwardUDP := flag.String("forwardudp", "", "UDP port mappings: LOCAL:REMOTE,LOCAL:REMOTE (used in vpn mode)")
	token := flag.String("token", "", "Authentication token (required on both sides)")
	strategy := flag.String("strategy", "failover", "Multi-relay strategy: failover or loadbalance")
	flag.Parse()

	if *token == "" {
		log.Fatal("Authentication token is required (-token)")
	}

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("Relay mode requires -port")
		}
		runRelay(*port, *token)
	case "vpn":
		if *host == "" || *port == "" {
			log.Fatal("VPN mode requires -host and -port")
		}
		
		mappings := parseForwardMappings(*forward, *forwardUDP)
		if len(mappings) == 0 {
			log.Fatal("VPN mode requires at least one -forward or -forwardudp mapping")
		}

		// Check if multiple hosts are specified
		hostList := strings.Split(*host, ",")
		if len(hostList) > 1 {
			// Multi-relay mode
			runVPNMulti(hostList, *port, *token, mappings, *strategy)
		} else {
			// Single relay mode (original behavior)
			runVPN(*host, *port, *token, mappings)
		}
	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}

// parseForwardMappings parses port mapping strings
func parseForwardMappings(tcpMappings, udpMappings string) []ForwardMapping {
	var result []ForwardMapping

	if tcpMappings != "" {
		for _, mapping := range strings.Split(tcpMappings, ",") {
			parts := strings.Split(strings.TrimSpace(mapping), ":")
			if len(parts) == 2 {
				result = append(result, ForwardMapping{
					LocalPort:  strings.TrimSpace(parts[0]),
					RemotePort: strings.TrimSpace(parts[1]),
					IsUDP:      false,
				})
			} else if len(parts) == 1 {
				// If only one port specified, use same for local and remote
				port := strings.TrimSpace(parts[0])
				result = append(result, ForwardMapping{
					LocalPort:  port,
					RemotePort: port,
					IsUDP:      false,
				})
			}
		}
	}

	if udpMappings != "" {
		for _, mapping := range strings.Split(udpMappings, ",") {
			parts := strings.Split(strings.TrimSpace(mapping), ":")
			if len(parts) == 2 {
				result = append(result, ForwardMapping{
					LocalPort:  strings.TrimSpace(parts[0]),
					RemotePort: strings.TrimSpace(parts[1]),
					IsUDP:      true,
				})
			} else if len(parts) == 1 {
				// If only one port specified, use same for local and remote
				port := strings.TrimSpace(parts[0])
				result = append(result, ForwardMapping{
					LocalPort:  port,
					RemotePort: port,
					IsUDP:      true,
				})
			}
		}
	}

	return result
}

// relay mode: listens for incoming tunnel connection from VPN client
func runRelay(port string, expectedToken string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Relay: failed to listen on port %s: %v", port, err)
	}
	log.Printf("Relay: listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Relay: failed to accept connection: %v", err)
			continue
		}
		log.Printf("Relay: accepted connection from %s", conn.RemoteAddr())

		go handleTunnel(conn, expectedToken)
	}
}

// handles a single tunnel connection from vpn client using smux with socket reuse
func handleTunnel(tunnelConn net.Conn, expectedToken string) {
	defer tunnelConn.Close()

	// Set deadline for authentication
	tunnelConn.SetDeadline(time.Now().Add(10 * time.Second))

	// Authenticate connection
	if !authenticateServer(tunnelConn, expectedToken) {
		log.Printf("Relay: authentication failed from %s", tunnelConn.RemoteAddr())
		return
	}

	// Clear deadline after successful authentication
	tunnelConn.SetDeadline(time.Time{})

	log.Printf("Relay: authenticated connection from %s", tunnelConn.RemoteAddr())

	// Create smux server session
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // 4MB
	smuxConfig.KeepAliveInterval = keepAliveInterval
	smuxConfig.KeepAliveTimeout = keepAliveTimeout
	smuxConfig.MaxFrameSize = bufferSize

	session, err := smux.Server(tunnelConn, smuxConfig)
	if err != nil {
		log.Printf("Relay: failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	log.Printf("Relay: smux session established")

	// Create relay session with listener tracking for socket reuse
	rs := &RelaySession{
		session:   session,
		listeners: make(map[string]net.Listener),
		udpConns:  make(map[string]*net.UDPConn),
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// Accept streams from the session
	go func() {
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("Relay: session closed: %v", err)
				close(stopChan)
				return
			}

			wg.Add(1)
			go func(s *smux.Stream) {
				defer wg.Done()
				handleRelayStream(s, rs)
			}(stream)
		}
	}()

	// Wait for session to close
	<-stopChan

	// Cleanup: close all listeners
	rs.mu.Lock()
	for port, listener := range rs.listeners {
		log.Printf("Relay: closing listener on port %s", port)
		listener.Close()
	}
	for port, udpConn := range rs.udpConns {
		log.Printf("Relay: closing UDP listener on port %s", port)
		udpConn.Close()
	}
	rs.mu.Unlock()

	// Wait for all streams to finish
	wg.Wait()
	log.Printf("Relay: connection from %s closed", tunnelConn.RemoteAddr())
}

// handleRelayStream processes individual streams - either setup or data forwarding
func handleRelayStream(stream *smux.Stream, rs *RelaySession) {
	defer stream.Close()

	// Read protocol type (1 byte: 0x01=TCP setup, 0x02=UDP setup, 0x03=TCP data, 0x04=UDP data)
	protocolBuf := make([]byte, 1)
	_, err := io.ReadFull(stream, protocolBuf)
	if err != nil {
		return
	}
	protocol := protocolBuf[0]

	// Use pooled small buffer for reading port
	bufPtr := smallBufPool.Get().(*[]byte)
	buf := *bufPtr
	n, err := stream.Read(buf)
	if err != nil {
		smallBufPool.Put(bufPtr)
		return
	}
	forwardPort := string(buf[:n])
	forwardPort = strings.TrimSpace(forwardPort)
	smallBufPool.Put(bufPtr)

	switch protocol {
	case 0x01: // TCP setup
		setupTCPForward(stream, forwardPort, rs)
	case 0x02: // UDP setup
		setupUDPForward(stream, forwardPort, rs)
	case 0x03: // TCP data connection
		handleTCPData(stream, forwardPort, rs)
	case 0x04: // UDP data
		handleUDPData(stream, forwardPort, rs)
	}
}

// setupTCPForward sets up TCP port forwarding
func setupTCPForward(stream *smux.Stream, forwardPort string, rs *RelaySession) {
	// Check if we already have a listener for this port (socket reuse)
	rs.mu.RLock()
	listener, exists := rs.listeners[forwardPort]
	rs.mu.RUnlock()

	if !exists {
		// Upgrade to write lock only if we need to create listener
		rs.mu.Lock()
		// Double-check after acquiring write lock
		listener, exists = rs.listeners[forwardPort]
		if !exists {
			// Create new listener
			var err error
			listener, err = net.Listen("tcp", ":"+forwardPort)
			if err != nil {
				rs.mu.Unlock()
				log.Printf("Relay: failed to listen on TCP port %s: %v", forwardPort, err)
				return
			}
			rs.listeners[forwardPort] = listener
			log.Printf("Relay: listening on TCP port %s (reusable socket)", forwardPort)

			// Start accepting connections on this port
			go acceptTCPConnections(listener, forwardPort, rs)
		} else {
			log.Printf("Relay: reusing existing TCP listener on port %s", forwardPort)
		}
		rs.mu.Unlock()
	}
}

// setupUDPForward sets up UDP port forwarding
func setupUDPForward(stream *smux.Stream, forwardPort string, rs *RelaySession) {
	rs.mu.RLock()
	udpConn, exists := rs.udpConns[forwardPort]
	rs.mu.RUnlock()

	if !exists {
		rs.mu.Lock()
		udpConn, exists = rs.udpConns[forwardPort]
		if !exists {
			addr, err := net.ResolveUDPAddr("udp", ":"+forwardPort)
			if err != nil {
				rs.mu.Unlock()
				log.Printf("Relay: failed to resolve UDP address for port %s: %v", forwardPort, err)
				return
			}

			udpConn, err = net.ListenUDP("udp", addr)
			if err != nil {
				rs.mu.Unlock()
				log.Printf("Relay: failed to listen on UDP port %s: %v", forwardPort, err)
				return
			}

			if err := udpConn.SetReadBuffer(udpBufferSize); err != nil {
				log.Printf("Relay: failed to set UDP read buffer: %v", err)
			}
			if err := udpConn.SetWriteBuffer(udpBufferSize); err != nil {
				log.Printf("Relay: failed to set UDP write buffer: %v", err)
			}

			rs.udpConns[forwardPort] = udpConn
			log.Printf("Relay: listening on UDP port %s (reusable socket)", forwardPort)

			go acceptUDPPackets(udpConn, forwardPort, rs)
		} else {
			log.Printf("Relay: reusing existing UDP listener on port %s", forwardPort)
		}
		rs.mu.Unlock()
	}
}

// handleTCPData handles incoming TCP data connections
func handleTCPData(stream *smux.Stream, forwardPort string, rs *RelaySession) {
	// This is called when relay opens a stream to send TCP connection to VPN client
	// The stream IS the connection, so this shouldn't be called on relay side
	log.Printf("Relay: unexpected TCP data stream for port %s", forwardPort)
}

// handleUDPData handles UDP data stream
func handleUDPData(stream *smux.Stream, forwardPort string, rs *RelaySession) {
	// This is called when relay opens a stream for UDP session
	// Should not be called on relay side
	log.Printf("Relay: unexpected UDP data stream for port %s", forwardPort)
}

// acceptTCPConnections handles accepting TCP connections for a specific port
func acceptTCPConnections(listener net.Listener, port string, rs *RelaySession) {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			// Listener was closed
			return
		}

		log.Printf("Relay: received TCP connection on port %s from %s", port, clientConn.RemoteAddr())

		// Spawn goroutine directly for each connection
		go func(conn net.Conn, p string, session *smux.Session) {
			// Open a new stream for this connection
			newStream, err := session.OpenStream()
			if err != nil {
				log.Printf("Relay: failed to open stream: %v", err)
				conn.Close()
				return
			}

			// Send protocol byte (0x03 = TCP data) and port identifier
			header := []byte{0x03}
			if _, err := newStream.Write(header); err != nil {
				newStream.Close()
				conn.Close()
				return
			}
			if _, err := newStream.Write([]byte(p + "\n")); err != nil {
				newStream.Close()
				conn.Close()
				return
			}

			log.Printf("Relay: forwarding TCP connection on port %s through tunnel", p)
			forwardWithPool(conn, newStream)
		}(clientConn, port, rs.session)
	}
}

// acceptUDPPackets handles UDP packets for a specific port
func acceptUDPPackets(udpConn *net.UDPConn, port string, rs *RelaySession) {
	sessions := &sync.Map{} // Map of client address -> UDPSession

	// Cleanup goroutine for expired sessions
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			sessions.Range(func(key, value interface{}) bool {
				sess := value.(*UDPSession)
				sess.mu.Lock()
				if now.Sub(sess.lastActive) > udpTimeout {
					close(sess.writeChan)
					sess.stream.Close()
					sessions.Delete(key)
					log.Printf("Relay: UDP session expired for %s on port %s", key, port)
				}
				sess.mu.Unlock()
				return true
			})
		}
	}()

	for {
		bufPtr := udpBufPool.Get().(*[]byte)
		buffer := *bufPtr
		n, addr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			udpBufPool.Put(bufPtr)
			return
		}

		addrKey := addr.String()

		// Get or create session
		var sess *UDPSession
		if val, ok := sessions.Load(addrKey); ok {
			sess = val.(*UDPSession)
			sess.mu.Lock()
			sess.lastActive = time.Now()
			sess.mu.Unlock()
		} else {
			// Create new session
			stream, err := rs.session.OpenStream()
			if err != nil {
				udpBufPool.Put(bufPtr)
				continue
			}

			// Send protocol byte (0x04 = UDP data), port, and client address
			header := []byte{0x04}
			addrBytes := []byte(addrKey)

			if _, err := stream.Write(header); err != nil {
				stream.Close()
				udpBufPool.Put(bufPtr)
				continue
			}
			if _, err := stream.Write([]byte(fmt.Sprintf("%s\n", port))); err != nil {
				stream.Close()
				udpBufPool.Put(bufPtr)
				continue
			}
			// Send address length and address
			addrLen := make([]byte, 2)
			binary.BigEndian.PutUint16(addrLen, uint16(len(addrBytes)))
			if _, err := stream.Write(addrLen); err != nil {
				stream.Close()
				udpBufPool.Put(bufPtr)
				continue
			}
			if _, err := stream.Write(addrBytes); err != nil {
				stream.Close()
				udpBufPool.Put(bufPtr)
				continue
			}

			sess = &UDPSession{
				clientAddr: addr,
				stream:     stream,
				lastActive: time.Now(),
				writeChan:  make(chan []byte, 256),
			}
			sessions.Store(addrKey, sess)

			log.Printf("Relay: new UDP session for %s on port %s", addrKey, port)

			// Handle incoming packets from VPN client (relay->client direction)
			go func(s *UDPSession, key string) {
				defer func() {
					s.stream.Close()
					sessions.Delete(key)
				}()

				readBuf := make([]byte, 65535) // Reuse buffer
				lenBuf := make([]byte, 4)       // Reuse length buffer
				for {
					if _, err := io.ReadFull(s.stream, lenBuf); err != nil {
						return
					}

					dataLen := binary.BigEndian.Uint32(lenBuf)
					if dataLen == 0 || dataLen > 65535 {
						return
					}

					if _, err := io.ReadFull(s.stream, readBuf[:dataLen]); err != nil {
						return
					}

					s.mu.Lock()
					s.lastActive = time.Now()
					s.mu.Unlock()

					udpConn.WriteToUDP(readBuf[:dataLen], s.clientAddr)
				}
			}(sess, addrKey)

			// Batched writer goroutine
			go func(s *UDPSession) {
				batch := make([]byte, 0, bufferSize)
				lenBuf := make([]byte, 4)

				timer := time.NewTimer(time.Millisecond)
				timer.Stop()
				packets := 0

				flush := func() {
					if len(batch) > 0 {
						s.stream.Write(batch)
						batch = batch[:0]
						packets = 0
					}
				}

				for {
					select {
					case data, ok := <-s.writeChan:
						if !ok {
							flush()
							return
						}

						binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

						if len(batch)+4+len(data) > cap(batch) {
							flush()
						}

						batch = append(batch, lenBuf...)
						batch = append(batch, data...)
						packets++

						if packets >= udpBatchSize {
							flush()
							timer.Stop()
						} else if packets == 1 {
							timer.Reset(time.Millisecond)
						}

					case <-timer.C:
						flush()
					}
				}
			}(sess)
		}

		// Send packet to VPN client
		data := make([]byte, n)
		copy(data, buffer[:n])
		udpBufPool.Put(bufPtr)

		select {
		case sess.writeChan <- data:
		default:
			// Drop packet if channel is full
		}
	}
}

// vpn mode: connects to relay server using smux with automatic reconnection (single relay)
func runVPN(relayHost, relayPort, clientToken string, mappings []ForwardMapping) {
	// Pre-compute the address string to avoid repeated allocations
	relayAddr := net.JoinHostPort(relayHost, relayPort)

	for {
		log.Printf("VPN: connecting to relay %s:%s", relayHost, relayPort)

		relayConn, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
		if err != nil {
			log.Printf("VPN: failed to connect to relay: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}
		log.Printf("VPN: connected to relay %s:%s", relayHost, relayPort)

		// Authenticate with relay
		if !authenticateClient(relayConn, clientToken) {
			log.Printf("VPN: authentication failed")
			relayConn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("VPN: authenticated with relay")

		// Create smux client session
		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024 // 4MB
		smuxConfig.KeepAliveInterval = keepAliveInterval
		smuxConfig.KeepAliveTimeout = keepAliveTimeout
		smuxConfig.MaxFrameSize = bufferSize

		session, err := smux.Client(relayConn, smuxConfig)
		if err != nil {
			log.Printf("VPN: failed to create smux session: %v", err)
			relayConn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("VPN: smux session established")

		// Declare sessionCloseChan early to avoid goto issues
		sessionCloseChan := make(chan struct{})

		// Send port mappings to relay
		for _, mapping := range mappings {
			if err := sendPortMapping(session, mapping); err != nil {
				log.Printf("VPN: failed to send port mapping: %v", err)
				session.Close()
				goto reconnect
			}
			if mapping.IsUDP {
				log.Printf("VPN: sent UDP port mapping %s -> %s", mapping.RemotePort, mapping.LocalPort)
			} else {
				log.Printf("VPN: sent TCP port mapping %s -> %s", mapping.RemotePort, mapping.LocalPort)
			}
		}

		// Monitor session health
		go func() {
			ticker := time.NewTicker(keepAliveInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if session.IsClosed() {
						log.Printf("VPN: session closed detected")
						close(sessionCloseChan)
						return
					}
				case <-sessionCloseChan:
					return
				}
			}
		}()

		// Handle incoming streams
		go func() {
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					log.Printf("VPN: failed to accept stream: %v", err)
					close(sessionCloseChan)
					return
				}

				log.Printf("VPN: accepted new stream")

				// Spawn goroutine directly for each stream
				go handleVPNStream(stream, mappings)
			}
		}()

		// Wait for session to close
		<-sessionCloseChan
		session.Close()
		relayConn.Close()

	reconnect:
		log.Printf("VPN: connection lost, reconnecting in %v", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

// runVPNMulti handles multiple relay connections with failover or load balancing
func runVPNMulti(hostList []string, port, token string, mappings []ForwardMapping, strategy string) {
	if len(hostList) == 0 {
		log.Fatal("No relay hosts provided")
	}

	for i := range hostList {
		hostList[i] = strings.TrimSpace(hostList[i])
	}

	log.Printf("VPN: Multi-relay mode with %d relays, strategy: %s", len(hostList), strategy)

	pool := &RelayPool{
		relays:   make([]*RelayConnection, len(hostList)),
		token:    token,
		mappings: mappings,
	}

	for i, host := range hostList {
		pool.relays[i] = &RelayConnection{
			host: host,
			port: port,
		}
		pool.relays[i].healthy.Store(false)
	}

	// Start maintaining connections to all relays
	for i, relay := range pool.relays {
		go pool.maintainConnection(i, relay)
	}

	// Start health monitor
	go pool.healthMonitor()

	// Keep main goroutine alive
	select {}
}

// maintainConnection maintains a connection to a single relay
func (p *RelayPool) maintainConnection(index int, relay *RelayConnection) {
	for {
		log.Printf("VPN: [Relay %d] Connecting to %s:%s", index, relay.host, relay.port)

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(relay.host, relay.port), 10*time.Second)
		if err != nil {
			log.Printf("VPN: [Relay %d] Failed to connect: %v", index, err)
			relay.healthy.Store(false)
			relay.failures.Add(1)
			time.Sleep(reconnectDelay)
			continue
		}

		if !authenticateClient(conn, p.token) {
			log.Printf("VPN: [Relay %d] Authentication failed", index)
			conn.Close()
			relay.healthy.Store(false)
			relay.failures.Add(1)
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("VPN: [Relay %d] Authenticated", index)

		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveInterval = keepAliveInterval
		smuxConfig.KeepAliveTimeout = keepAliveTimeout
		smuxConfig.MaxFrameSize = bufferSize
		smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024

		session, err := smux.Client(conn, smuxConfig)
		if err != nil {
			log.Printf("VPN: [Relay %d] Failed to create smux session: %v", index, err)
			conn.Close()
			relay.healthy.Store(false)
			relay.failures.Add(1)
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("VPN: [Relay %d] Session established", index)

		relay.mu.Lock()
		relay.session = session
		relay.conn = conn
		relay.lastSuccess = time.Now()
		relay.mu.Unlock()
		relay.healthy.Store(true)
		relay.failures.Store(0)

		// Send port mappings
		for _, mapping := range p.mappings {
			if err := sendPortMapping(session, mapping); err != nil {
				log.Printf("VPN: [Relay %d] Failed to send port mapping %s:%s: %v", index, mapping.RemotePort, mapping.LocalPort, err)
			} else {
				if mapping.IsUDP {
					log.Printf("VPN: [Relay %d] Setup UDP forward %s -> %s", index, mapping.RemotePort, mapping.LocalPort)
				} else {
					log.Printf("VPN: [Relay %d] Setup TCP forward %s -> %s", index, mapping.RemotePort, mapping.LocalPort)
				}
			}
		}

		// Handle incoming streams
		go func() {
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				go handleVPNStream(stream, p.mappings)
			}
		}()

		// Monitor session health
		for {
			time.Sleep(keepAliveInterval)
			if session.IsClosed() {
				break
			}
		}

		relay.mu.Lock()
		relay.session = nil
		relay.conn = nil
		relay.mu.Unlock()
		relay.healthy.Store(false)

		session.Close()
		conn.Close()

		log.Printf("VPN: [Relay %d] Connection lost, reconnecting in %v", index, reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

// healthMonitor periodically reports relay health status
func (p *RelayPool) healthMonitor() {
	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()

	for range ticker.C {
		healthy := 0
		for i, relay := range p.relays {
			if relay.healthy.Load() {
				healthy++
				log.Printf("VPN: [Relay %d] Status: HEALTHY", i)
			} else {
				log.Printf("VPN: [Relay %d] Status: UNHEALTHY (failures: %d)", i, relay.failures.Load())
			}
		}
		log.Printf("VPN: Total healthy relays: %d/%d", healthy, len(p.relays))
	}
}

// sendPortMapping sends a port mapping setup to the relay
func sendPortMapping(session *smux.Session, mapping ForwardMapping) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	var protocol byte
	if mapping.IsUDP {
		protocol = 0x02 // UDP setup
	} else {
		protocol = 0x01 // TCP setup
	}

	// Send protocol byte and port
	if _, err := stream.Write([]byte{protocol}); err != nil {
		return err
	}
	if _, err := stream.Write([]byte(mapping.RemotePort + "\n")); err != nil {
		return err
	}

	return nil
}

// handleVPNStream processes a single stream from relay to local service
func handleVPNStream(stream *smux.Stream, mappings []ForwardMapping) {
	defer stream.Close()

	// Read protocol byte
	protocolBuf := make([]byte, 1)
	_, err := io.ReadFull(stream, protocolBuf)
	if err != nil {
		return
	}
	protocol := protocolBuf[0]

	// Use pooled small buffer for reading port identifier
	bufPtr := smallBufPool.Get().(*[]byte)
	buf := *bufPtr
	n, err := stream.Read(buf)
	smallBufPool.Put(bufPtr)
	if err != nil {
		return
	}
	remotePort := strings.TrimSpace(string(buf[:n]))

	// Find matching mapping
	var localPort string
	for _, m := range mappings {
		if m.RemotePort == remotePort {
			localPort = m.LocalPort
			break
		}
	}

	if localPort == "" {
		log.Printf("VPN: no mapping found for port %s", remotePort)
		return
	}

	switch protocol {
	case 0x03: // TCP data
		handleVPNTCP(stream, localPort)
	case 0x04: // UDP data
		handleVPNUDP(stream, localPort)
	}
}

// handleVPNTCP handles TCP forwarding to local service
func handleVPNTCP(stream *smux.Stream, localPort string) {
	localAddr := "127.0.0.1:" + localPort

	// Connect to local service
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		log.Printf("VPN: failed to connect to localhost:%s: %v", localPort, err)
		return
	}

	log.Printf("VPN: forwarding TCP stream to %s", localAddr)
	forwardWithPool(stream, localConn)
}

// handleVPNUDP handles UDP forwarding to local service
func handleVPNUDP(stream *smux.Stream, localPort string) {
	// Read client address
	addrLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, addrLenBuf); err != nil {
		return
	}
	addrLen := binary.BigEndian.Uint16(addrLenBuf)

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		return
	}
	clientAddr := string(addrBuf)

	log.Printf("VPN: forwarding UDP stream to localhost:%s (client: %s)", localPort, clientAddr)

	localAddr := "127.0.0.1:" + localPort
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Printf("VPN: failed to resolve UDP address: %v", err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("VPN: failed to dial UDP: %v", err)
		return
	}
	defer udpConn.Close()

	if err := udpConn.SetReadBuffer(udpBufferSize); err != nil {
		log.Printf("VPN: failed to set UDP read buffer: %v", err)
	}
	if err := udpConn.SetWriteBuffer(udpBufferSize); err != nil {
		log.Printf("VPN: failed to set UDP write buffer: %v", err)
	}

	var wg sync.WaitGroup

	// Read from stream, write to local UDP
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer udpConn.Close() // Close UDP to unblock read goroutine

		readBuf := make([]byte, 65535) // Reuse buffer
		lenBuf := make([]byte, 4)       // Reuse length buffer
		for {
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}

			dataLen := binary.BigEndian.Uint32(lenBuf)
			if dataLen == 0 || dataLen > 65535 {
				return
			}

			if _, err := io.ReadFull(stream, readBuf[:dataLen]); err != nil {
				return
			}

			if _, err := udpConn.Write(readBuf[:dataLen]); err != nil {
				return
			}
		}
	}()

	// Read from local UDP, write to stream
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stream.Close() // Close stream to unblock write goroutine

		buffer := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buffer)
			if err != nil {
				return
			}

			// Write length and data
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := stream.Write(lenBuf); err != nil {
				return
			}
			if _, err := stream.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// forwardWithPool performs bidirectional copy using buffer pool
func forwardWithPool(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy a -> b
	go func() {
		defer wg.Done()
		copyWithPool(b, a)
	}()

	// Copy b -> a
	go func() {
		defer wg.Done()
		copyWithPool(a, b)
	}()

	wg.Wait()
}

// copyWithPool copies data from src to dst using pooled buffers
func copyWithPool(dst io.Writer, src io.Reader) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	buf := *bufPtr

	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil && err != io.EOF {
		// Suppress logging for common errors
		if !isClosedConnError(err) {
			log.Printf("Copy error: %v", err)
		}
	}
}

// authenticateServer handles server-side authentication
func authenticateServer(conn net.Conn, expectedToken string) bool {
	// Read token from client
	tokenBuf := make([]byte, 256)
	n, err := conn.Read(tokenBuf)
	if err != nil {
		return false
	}

	receivedToken := strings.TrimSpace(string(tokenBuf[:n]))

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(receivedToken), []byte(expectedToken)) != 1 {
		// Send failure response
		conn.Write([]byte{0x00})
		return false
	}

	// Send success response
	_, err = conn.Write([]byte{0x01})
	return err == nil
}

// authenticateClient handles client-side authentication
func authenticateClient(conn net.Conn, token string) bool {
	// Send token to server
	_, err := conn.Write([]byte(token))
	if err != nil {
		return false
	}

	// Read authentication response
	response := make([]byte, 1)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false
	}

	return response[0] == 0x01
}

// isClosedConnError checks if error is due to closed connection
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer")
}
