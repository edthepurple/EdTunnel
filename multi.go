package main

import (
	"crypto/rand"
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
	keepAliveInterval = 10 * time.Second
	keepAliveTimeout  = 30 * time.Second
	reconnectDelay    = 2 * time.Second
	udpTimeout        = 90 * time.Second
	bufferSize        = 32 * 1024
	udpBufferSize     = 64 * 1024
	udpBatchSize      = 16
	healthCheckPeriod = 5 * time.Second
)

type ForwardMapping struct {
	SrcPort    string
	TargetPort string
	IsUDP      bool
}

type RelaySession struct {
	session   *smux.Session
	listeners map[string]net.Listener
	udpConns  map[string]*net.UDPConn
	mu        sync.Mutex
}

type UDPSession struct {
	clientAddr *net.UDPAddr
	stream     *smux.Stream
	lastActive time.Time
	writeChan  chan []byte
	mu         sync.Mutex
}

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
	forward := flag.String("forward", "", "TCP port mappings: SRC:TARGET,SRC:TARGET (used in vpn mode)")
	forwardUDP := flag.String("forwardudp", "", "UDP port mappings: SRC:TARGET,SRC:TARGET (used in vpn mode)")
	token := flag.String("token", "", "Authentication token")
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
		runVPNMulti(*host, *port, *token, mappings, *strategy)
	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}

func parseForwardMappings(tcpMappings, udpMappings string) []ForwardMapping {
	var result []ForwardMapping

	if tcpMappings != "" {
		for _, mapping := range strings.Split(tcpMappings, ",") {
			parts := strings.Split(strings.TrimSpace(mapping), ":")
			if len(parts) == 2 {
				result = append(result, ForwardMapping{
					SrcPort:    strings.TrimSpace(parts[0]),
					TargetPort: strings.TrimSpace(parts[1]),
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
					SrcPort:    strings.TrimSpace(parts[0]),
					TargetPort: strings.TrimSpace(parts[1]),
					IsUDP:      true,
				})
			}
		}
	}

	return result
}

func runRelay(port, token string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Relay: failed to listen on port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("Relay: listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Relay: failed to accept connection: %v", err)
			continue
		}

		go handleRelayConnection(conn, token)
	}
}

func handleRelayConnection(conn net.Conn, expectedToken string) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !authenticate(conn, expectedToken, false) {
		log.Printf("Relay: authentication failed from %s", conn.RemoteAddr())
		return
	}
	conn.SetDeadline(time.Time{})

	log.Printf("Relay: authenticated connection from %s", conn.RemoteAddr())

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = keepAliveInterval
	smuxConfig.KeepAliveTimeout = keepAliveTimeout
	smuxConfig.MaxFrameSize = bufferSize
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024

	session, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("Relay: failed to create smux session: %v", err)
		return
	}
	defer session.Close()

	log.Printf("Relay: smux session established")

	rs := &RelaySession{
		session:   session,
		listeners: make(map[string]net.Listener),
		udpConns:  make(map[string]*net.UDPConn),
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

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

	<-stopChan

	rs.mu.Lock()
	for _, l := range rs.listeners {
		l.Close()
	}
	for _, u := range rs.udpConns {
		u.Close()
	}
	rs.mu.Unlock()

	wg.Wait()
	log.Printf("Relay: connection from %s closed", conn.RemoteAddr())
}

func handleRelayStream(stream *smux.Stream, rs *RelaySession) {
	defer stream.Close()

	header := make([]byte, 1)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	msgType := header[0]

	switch msgType {
	case 0x01:
		handleTCPForward(stream, rs)
	case 0x02:
		handleUDPForward(stream, rs)
	}
}

func handleTCPForward(stream *smux.Stream, rs *RelaySession) {
	portLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, portLen); err != nil {
		return
	}

	portBytes := make([]byte, binary.BigEndian.Uint16(portLen))
	if _, err := io.ReadFull(stream, portBytes); err != nil {
		return
	}
	srcPort := string(portBytes)

	rs.mu.Lock()
	listener, exists := rs.listeners[srcPort]
	if !exists {
		var err error
		listener, err = net.Listen("tcp", ":"+srcPort)
		if err != nil {
			rs.mu.Unlock()
			log.Printf("Relay: failed to listen on TCP port %s: %v", srcPort, err)
			return
		}
		rs.listeners[srcPort] = listener
		log.Printf("Relay: listening on TCP port %s", srcPort)

		go func(l net.Listener, port string) {
			for {
				clientConn, err := l.Accept()
				if err != nil {
					return
				}
				go handleTCPClient(clientConn, port, rs.session)
			}
		}(listener, srcPort)
	}
	rs.mu.Unlock()
}

func handleTCPClient(clientConn net.Conn, srcPort string, session *smux.Session) {
	defer clientConn.Close()

	stream, err := session.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	header := []byte{0x04}
	portBytes := []byte(srcPort)
	portLen := make([]byte, 2)
	binary.BigEndian.PutUint16(portLen, uint16(len(portBytes)))

	if _, err := stream.Write(header); err != nil {
		return
	}
	if _, err := stream.Write(portLen); err != nil {
		return
	}
	if _, err := stream.Write(portBytes); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, clientConn)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, stream)
		clientConn.Close()
	}()

	wg.Wait()
}

func handleUDPForward(stream *smux.Stream, rs *RelaySession) {
	portLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, portLen); err != nil {
		return
	}

	portBytes := make([]byte, binary.BigEndian.Uint16(portLen))
	if _, err := io.ReadFull(stream, portBytes); err != nil {
		return
	}
	srcPort := string(portBytes)

	rs.mu.Lock()
	udpConn, exists := rs.udpConns[srcPort]
	if !exists {
		addr, err := net.ResolveUDPAddr("udp", ":"+srcPort)
		if err != nil {
			rs.mu.Unlock()
			return
		}
		udpConn, err = net.ListenUDP("udp", addr)
		if err != nil {
			rs.mu.Unlock()
			log.Printf("Relay: failed to listen on UDP port %s: %v", srcPort, err)
			return
		}

		if err := udpConn.SetReadBuffer(udpBufferSize); err != nil {
			log.Printf("Relay: failed to set UDP read buffer: %v", err)
		}
		if err := udpConn.SetWriteBuffer(udpBufferSize); err != nil {
			log.Printf("Relay: failed to set UDP write buffer: %v", err)
		}

		rs.udpConns[srcPort] = udpConn
		log.Printf("Relay: listening on UDP port %s", srcPort)

		go handleUDPListener(udpConn, srcPort, rs.session)
	}
	rs.mu.Unlock()
}

func handleUDPListener(udpConn *net.UDPConn, srcPort string, session *smux.Session) {
	sessions := &sync.Map{}

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
				}
				sess.mu.Unlock()
				return true
			})
		}
	}()

	packetPool := sync.Pool{
		New: func() interface{} {
			return make([]byte, 2048)
		},
	}

	for {
		buffer := packetPool.Get().([]byte)
		n, addr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			packetPool.Put(buffer)
			return
		}

		addrKey := addr.String()

		var sess *UDPSession
		if val, ok := sessions.Load(addrKey); ok {
			sess = val.(*UDPSession)
			sess.mu.Lock()
			sess.lastActive = time.Now()
			sess.mu.Unlock()
		} else {
			stream, err := session.OpenStream()
			if err != nil {
				packetPool.Put(buffer)
				continue
			}

			header := []byte{0x05}
			portBytes := []byte(srcPort)
			portLen := make([]byte, 2)
			binary.BigEndian.PutUint16(portLen, uint16(len(portBytes)))

			addrBytes := []byte(addrKey)
			addrLen := make([]byte, 2)
			binary.BigEndian.PutUint16(addrLen, uint16(len(addrBytes)))

			if _, err := stream.Write(header); err != nil {
				stream.Close()
				packetPool.Put(buffer)
				continue
			}
			if _, err := stream.Write(portLen); err != nil {
				stream.Close()
				packetPool.Put(buffer)
				continue
			}
			if _, err := stream.Write(portBytes); err != nil {
				stream.Close()
				packetPool.Put(buffer)
				continue
			}
			if _, err := stream.Write(addrLen); err != nil {
				stream.Close()
				packetPool.Put(buffer)
				continue
			}
			if _, err := stream.Write(addrBytes); err != nil {
				stream.Close()
				packetPool.Put(buffer)
				continue
			}

			sess = &UDPSession{
				clientAddr: addr,
				stream:     stream,
				lastActive: time.Now(),
				writeChan:  make(chan []byte, 256),
			}
			sessions.Store(addrKey, sess)

			go func(s *UDPSession, key string) {
				defer func() {
					s.stream.Close()
					sessions.Delete(key)
				}()

				readBuffer := make([]byte, 65535)
				for {
					lenBuf := make([]byte, 4)
					if _, err := io.ReadFull(s.stream, lenBuf); err != nil {
						return
					}

					dataLen := binary.BigEndian.Uint32(lenBuf)
					if dataLen == 0 || dataLen > 65535 {
						return
					}

					if _, err := io.ReadFull(s.stream, readBuffer[:dataLen]); err != nil {
						return
					}

					s.mu.Lock()
					s.lastActive = time.Now()
					s.mu.Unlock()

					udpConn.WriteToUDP(readBuffer[:dataLen], s.clientAddr)
				}
			}(sess, addrKey)

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

		data := make([]byte, n)
		copy(data, buffer[:n])
		packetPool.Put(buffer)

		select {
		case sess.writeChan <- data:
		default:
		}
	}
}

func runVPNMulti(hosts, port, token string, mappings []ForwardMapping, strategy string) {
	hostList := strings.Split(hosts, ",")
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

	for i, relay := range pool.relays {
		go pool.maintainConnection(i, relay)
	}

	go pool.healthMonitor()

	if strategy == "loadbalance" {
		pool.runLoadBalanced()
	} else {
		pool.runFailover()
	}
}

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

		if !authenticate(conn, p.token, true) {
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

		for _, mapping := range p.mappings {
			if mapping.IsUDP {
				if err := setupUDPForward(session, mapping); err != nil {
					log.Printf("VPN: [Relay %d] Failed to setup UDP forward %s:%s: %v", index, mapping.SrcPort, mapping.TargetPort, err)
				} else {
					log.Printf("VPN: [Relay %d] Setup UDP forward %s -> %s", index, mapping.SrcPort, mapping.TargetPort)
				}
			} else {
				if err := setupTCPForward(session, mapping); err != nil {
					log.Printf("VPN: [Relay %d] Failed to setup TCP forward %s:%s: %v", index, mapping.SrcPort, mapping.TargetPort, err)
				} else {
					log.Printf("VPN: [Relay %d] Setup TCP forward %s -> %s", index, mapping.SrcPort, mapping.TargetPort)
				}
			}
		}

		go handleVPNStreams(session, p.mappings)

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

func (p *RelayPool) getHealthyRelay() *RelayConnection {
	for _, relay := range p.relays {
		if relay.healthy.Load() {
			relay.mu.RLock()
			session := relay.session
			relay.mu.RUnlock()
			if session != nil && !session.IsClosed() {
				return relay
			}
		}
	}
	return nil
}

func (p *RelayPool) getNextRelay() *RelayConnection {
	for i := 0; i < len(p.relays); i++ {
		idx := p.current.Add(1) % uint32(len(p.relays))
		relay := p.relays[idx]
		if relay.healthy.Load() {
			relay.mu.RLock()
			session := relay.session
			relay.mu.RUnlock()
			if session != nil && !session.IsClosed() {
				return relay
			}
		}
	}
	return nil
}

func (p *RelayPool) runFailover() {
	select {}
}

func (p *RelayPool) runLoadBalanced() {
	select {}
}

func setupTCPForward(session *smux.Session, mapping ForwardMapping) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	header := []byte{0x01}
	portBytes := []byte(mapping.SrcPort)
	portLen := make([]byte, 2)
	binary.BigEndian.PutUint16(portLen, uint16(len(portBytes)))

	if _, err := stream.Write(header); err != nil {
		return err
	}
	if _, err := stream.Write(portLen); err != nil {
		return err
	}
	if _, err := stream.Write(portBytes); err != nil {
		return err
	}

	return nil
}

func setupUDPForward(session *smux.Session, mapping ForwardMapping) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	header := []byte{0x02}
	portBytes := []byte(mapping.SrcPort)
	portLen := make([]byte, 2)
	binary.BigEndian.PutUint16(portLen, uint16(len(portBytes)))

	if _, err := stream.Write(header); err != nil {
		return err
	}
	if _, err := stream.Write(portLen); err != nil {
		return err
	}
	if _, err := stream.Write(portBytes); err != nil {
		return err
	}

	return nil
}

func handleVPNStreams(session *smux.Session, mappings []ForwardMapping) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}

		go handleVPNStream(stream, mappings)
	}
}

func handleVPNStream(stream *smux.Stream, mappings []ForwardMapping) {
	defer stream.Close()

	header := make([]byte, 1)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	msgType := header[0]

	switch msgType {
	case 0x04:
		handleTCPConnection(stream, mappings)
	case 0x05:
		handleUDPConnection(stream, mappings)
	}
}

func handleTCPConnection(stream *smux.Stream, mappings []ForwardMapping) {
	portLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, portLen); err != nil {
		return
	}

	portBytes := make([]byte, binary.BigEndian.Uint16(portLen))
	if _, err := io.ReadFull(stream, portBytes); err != nil {
		return
	}
	srcPort := string(portBytes)

	var targetPort string
	for _, m := range mappings {
		if m.SrcPort == srcPort && !m.IsUDP {
			targetPort = m.TargetPort
			break
		}
	}

	if targetPort == "" {
		return
	}

	localConn, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
	if err != nil {
		return
	}
	defer localConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(localConn, stream)
		localConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, localConn)
		stream.Close()
	}()

	wg.Wait()
}

func handleUDPConnection(stream *smux.Stream, mappings []ForwardMapping) {
	defer stream.Close()

	portLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, portLen); err != nil {
		return
	}

	portBytes := make([]byte, binary.BigEndian.Uint16(portLen))
	if _, err := io.ReadFull(stream, portBytes); err != nil {
		return
	}
	srcPort := string(portBytes)

	addrLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, addrLen); err != nil {
		return
	}

	addrBytes := make([]byte, binary.BigEndian.Uint16(addrLen))
	if _, err := io.ReadFull(stream, addrBytes); err != nil {
		return
	}

	var targetPort string
	for _, m := range mappings {
		if m.SrcPort == srcPort && m.IsUDP {
			targetPort = m.TargetPort
			break
		}
	}

	if targetPort == "" {
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
	if err != nil {
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer udpConn.Close()

	if err := udpConn.SetReadBuffer(udpBufferSize); err != nil {
		log.Printf("VPN: failed to set UDP read buffer: %v", err)
	}
	if err := udpConn.SetWriteBuffer(udpBufferSize); err != nil {
		log.Printf("VPN: failed to set UDP write buffer: %v", err)
	}

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	writeChan := make(chan []byte, 256)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writeChan)

		buffer := make([]byte, 65535)
		for {
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				close(stopChan)
				return
			}

			dataLen := binary.BigEndian.Uint32(lenBuf)
			if dataLen == 0 || dataLen > 65535 {
				close(stopChan)
				return
			}

			if _, err := io.ReadFull(stream, buffer[:dataLen]); err != nil {
				close(stopChan)
				return
			}

			data := make([]byte, dataLen)
			copy(data, buffer[:dataLen])

			select {
			case writeChan <- data:
			case <-stopChan:
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case data, ok := <-writeChan:
				if !ok {
					return
				}
				udpConn.Write(data)
			case <-stopChan:
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		batch := make([]byte, 0, bufferSize)
		lenBuf := make([]byte, 4)
		buffer := make([]byte, 2048)
		packets := 0

		timer := time.NewTimer(time.Millisecond)
		timer.Stop()

		readChan := make(chan []byte, 256)

		go func() {
			for {
				n, err := udpConn.Read(buffer)
				if err != nil {
					close(readChan)
					return
				}

				data := make([]byte, n)
				copy(data, buffer[:n])

				select {
				case readChan <- data:
				case <-stopChan:
					close(readChan)
					return
				}
			}
		}()

		flush := func() {
			if len(batch) > 0 {
				stream.Write(batch)
				batch = batch[:0]
				packets = 0
			}
		}

		for {
			select {
			case data, ok := <-readChan:
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

			case <-stopChan:
				flush()
				return
			}
		}
	}()

	wg.Wait()
}

func authenticate(conn net.Conn, token string, isClient bool) bool {
	challenge := make([]byte, 32)
	if isClient {
		if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
			return false
		}
		if _, err := conn.Write(challenge); err != nil {
			return false
		}

		expectedResponse := computeResponse(challenge, token)
		response := make([]byte, len(expectedResponse))
		if _, err := io.ReadFull(conn, response); err != nil {
			return false
		}

		if string(response) != expectedResponse {
			return false
		}

		ack := []byte{0x01}
		if _, err := conn.Write(ack); err != nil {
			return false
		}
	} else {
		if _, err := io.ReadFull(conn, challenge); err != nil {
			return false
		}

		response := computeResponse(challenge, token)
		if _, err := conn.Write([]byte(response)); err != nil {
			return false
		}

		ack := make([]byte, 1)
		if _, err := io.ReadFull(conn, ack); err != nil {
			return false
		}

		if ack[0] != 0x01 {
			return false
		}
	}

	return true
}

func computeResponse(challenge []byte, token string) string {
	combined := append(challenge, []byte(token)...)
	hash := uint64(0)
	for _, b := range combined {
		hash = hash*31 + uint64(b)
	}
	return fmt.Sprintf("%016x", hash)
}
