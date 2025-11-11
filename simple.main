// +build linux

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const (
	bufferSize        = 128 * 1024
	udpBufferSize     = 65535
	idleTimeout       = 5 * time.Minute
	reconnectDelay    = 3 * time.Second
	keepAliveInterval = 30 * time.Second

	smuxVersion          = 1
	smuxMaxFrameSize     = 16384
	smuxMaxReceiveBuffer = 4194304
)

type PortMapping struct {
	RelayPort string
	VPNPort   string
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, bufferSize)
		return &buf
	},
}

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, udpBufferSize)
		return &buf
	},
}

type Config struct {
	Mode       string
	Host       string
	Port       string
	Token      string
	Forward    string
	ForwardUDP string
}

func parsePortMappings(portList string) ([]PortMapping, error) {
	if portList == "" {
		return nil, nil
	}

	var mappings []PortMapping
	ports := strings.Split(portList, ";")

	for _, portStr := range ports {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		parts := strings.Split(portStr, ",")

		if len(parts) == 1 {
			port := strings.TrimSpace(parts[0])
			mappings = append(mappings, PortMapping{
				RelayPort: port,
				VPNPort:   port,
			})
		} else if len(parts) == 2 {
			relayPort := strings.TrimSpace(parts[0])
			vpnPort := strings.TrimSpace(parts[1])

			mappings = append(mappings, PortMapping{
				RelayPort: relayPort,
				VPNPort:   vpnPort,
			})
		} else {
			return nil, fmt.Errorf("invalid port mapping format: %s", portStr)
		}
	}

	return mappings, nil
}

type RelayServer struct {
	config   *Config
	sessions sync.Map
}

type Session struct {
	muxSession    *smux.Session
	tcpMappings   []PortMapping
	udpMappings   []PortMapping
	token         string
	ctx           context.Context
	cancel        context.CancelFunc
	tcpListeners  []net.Listener
	udpConns      []*net.UDPConn
	udpForwarders []*UDPForwarder
}

type UDPForwarder struct {
	sessions  sync.Map
	session   *smux.Session
	vpnPort   string
	relayPort string
	udpConn   *net.UDPConn
}

type UDPSession struct {
	stream     *smux.Stream
	clientAddr *net.UDPAddr
	lastSeen   time.Time
	mu         sync.RWMutex
}

func (us *UDPSession) UpdateActivity() {
	us.mu.Lock()
	us.lastSeen = time.Now()
	us.mu.Unlock()
}

func (us *UDPSession) IsStale() bool {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return time.Since(us.lastSeen) > idleTimeout
}

func NewRelayServer(config *Config) *RelayServer {
	return &RelayServer{
		config: config,
	}
}

func (r *RelayServer) Start() error {
	listener, err := net.Listen("tcp", ":"+r.config.Port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Relay: listening on port %s", r.config.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Relay: accept error: %v", err)
			continue
		}
		go r.handleConnection(conn)
	}
}

func (r *RelayServer) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	defer conn.Close()

	// Read token
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	tokenBuf := make([]byte, 256)
	n, err := conn.Read(tokenBuf)
	if err != nil {
		log.Printf("Relay: failed to read token from %s: %v", remoteAddr, err)
		return
	}

	receivedToken := strings.TrimSpace(string(tokenBuf[:n]))
	if receivedToken != r.config.Token {
		log.Printf("Relay: invalid token from %s", remoteAddr)
		return
	}

	// Send ACK
	conn.Write([]byte("OK\n"))
	conn.SetReadDeadline(time.Time{})

	// Create smux session
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = smuxVersion
	smuxConfig.MaxFrameSize = smuxMaxFrameSize
	smuxConfig.MaxReceiveBuffer = smuxMaxReceiveBuffer
	smuxConfig.KeepAliveInterval = keepAliveInterval
	smuxConfig.KeepAliveTimeout = keepAliveInterval * 2

	muxSession, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("Relay: failed to create smux session: %v", err)
		return
	}
	defer muxSession.Close()

	// Accept control stream
	controlStream, err := muxSession.AcceptStream()
	if err != nil {
		log.Printf("Relay: failed to accept control stream: %v", err)
		return
	}

	reader := bufio.NewReader(controlStream)

	// Read forward ports
	forwardLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		return
	}
	forwardPortsStr := strings.TrimSpace(forwardLine)

	// Read forward UDP ports
	forwardUDPLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		return
	}
	forwardUDPPortsStr := strings.TrimSpace(forwardUDPLine)

	controlStream.Close()

	// Parse port mappings
	tcpMappings, err := parsePortMappings(forwardPortsStr)
	if err != nil {
		log.Printf("Relay: invalid TCP ports: %v", err)
		return
	}

	udpMappings, err := parsePortMappings(forwardUDPPortsStr)
	if err != nil {
		log.Printf("Relay: invalid UDP ports: %v", err)
		return
	}

	if len(tcpMappings) == 0 && len(udpMappings) == 0 {
		log.Printf("Relay: no forward ports specified")
		return
	}

	log.Printf("Relay: authenticated connection from %s, TCP: %v, UDP: %v", remoteAddr, tcpMappings, udpMappings)

	// Close existing session if any
	sessionKey := receivedToken
	if oldSession, exists := r.sessions.Load(sessionKey); exists {
		log.Printf("Relay: closing existing session")
		oldSession.(*Session).cancel()
		r.sessions.Delete(sessionKey)
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		muxSession:  muxSession,
		tcpMappings: tcpMappings,
		udpMappings: udpMappings,
		token:       receivedToken,
		ctx:         ctx,
		cancel:      cancel,
	}

	r.sessions.Store(sessionKey, session)

	// Start TCP forwarding
	for _, mapping := range tcpMappings {
		if err := r.startTCPForwarding(session, mapping); err != nil {
			log.Printf("Relay: failed to start TCP forwarding: %v", err)
			cancel()
			return
		}
	}

	// Start UDP forwarding
	for _, mapping := range udpMappings {
		if err := r.startUDPForwarding(session, mapping); err != nil {
			log.Printf("Relay: failed to start UDP forwarding: %v", err)
			cancel()
			return
		}
	}

	// Wait for session to end
	<-ctx.Done()
	r.cleanupSession(session, sessionKey)
}

func (r *RelayServer) startTCPForwarding(session *Session, mapping PortMapping) error {
	listener, err := net.Listen("tcp", ":"+mapping.RelayPort)
	if err != nil {
		return err
	}
	session.tcpListeners = append(session.tcpListeners, listener)

	log.Printf("Relay: TCP forwarding on port %s -> %s", mapping.RelayPort, mapping.VPNPort)

	go func(l net.Listener, m PortMapping) {
		defer l.Close()

		for {
			select {
			case <-session.ctx.Done():
				return
			default:
			}

			conn, err := l.Accept()
			if err != nil {
				if session.ctx.Err() != nil {
					return
				}
				continue
			}

			go r.handleTCPClient(session, conn, m.VPNPort)
		}
	}(listener, mapping)

	return nil
}

func (r *RelayServer) handleTCPClient(session *Session, conn net.Conn, vpnPort string) {
	defer conn.Close()

	stream, err := session.muxSession.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// Send protocol message
	protocolMsg := fmt.Sprintf("TCP:%s\n", vpnPort)
	_, err = stream.Write([]byte(protocolMsg))
	if err != nil {
		return
	}

	// Bidirectional copy
	done := make(chan error, 2)

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(stream, conn, *bufPtr)
		stream.Close()
		done <- err
	}()

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(conn, stream, *bufPtr)
		conn.Close()
		done <- err
	}()

	<-done
	<-done
}

func (r *RelayServer) startUDPForwarding(session *Session, mapping PortMapping) error {
	addr, err := net.ResolveUDPAddr("udp", ":"+mapping.RelayPort)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	session.udpConns = append(session.udpConns, conn)

	forwarder := &UDPForwarder{
		session:   session.muxSession,
		vpnPort:   mapping.VPNPort,
		relayPort: mapping.RelayPort,
		udpConn:   conn,
	}

	session.udpForwarders = append(session.udpForwarders, forwarder)

	log.Printf("Relay: UDP forwarding on port %s -> %s", mapping.RelayPort, mapping.VPNPort)

	go r.handleUDPForwarder(session, forwarder)

	return nil
}

func (r *RelayServer) handleUDPForwarder(session *Session, forwarder *UDPForwarder) {
	defer forwarder.udpConn.Close()

	bufPtr := udpBufferPool.Get().(*[]byte)
	defer udpBufferPool.Put(bufPtr)
	buf := *bufPtr

	// Cleanup stale sessions
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			select {
			case <-session.ctx.Done():
				return
			default:
				forwarder.sessions.Range(func(key, value interface{}) bool {
					udpSess := value.(*UDPSession)
					if udpSess.IsStale() {
						udpSess.stream.Close()
						forwarder.sessions.Delete(key)
					}
					return true
				})
			}
		}
	}()

	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}

		n, clientAddr, err := forwarder.udpConn.ReadFromUDP(buf)
		if err != nil {
			if session.ctx.Err() != nil {
				return
			}
			continue
		}

		addrKey := clientAddr.String()

		sessVal, exists := forwarder.sessions.Load(addrKey)
		if !exists {
			stream, err := forwarder.session.OpenStream()
			if err != nil {
				continue
			}

			// Send protocol message
			protocolMsg := fmt.Sprintf("UDP:%s\n", forwarder.vpnPort)
			_, err = stream.Write([]byte(protocolMsg))
			if err != nil {
				stream.Close()
				continue
			}

			udpSess := &UDPSession{
				stream:     stream,
				clientAddr: clientAddr,
				lastSeen:   time.Now(),
			}

			forwarder.sessions.Store(addrKey, udpSess)
			sessVal = udpSess

			go func(us *UDPSession, fwd *UDPForwarder) {
				defer us.stream.Close()
				defer fwd.sessions.Delete(addrKey)

				bufPtr := udpBufferPool.Get().(*[]byte)
				defer udpBufferPool.Put(bufPtr)
				rbuf := *bufPtr

				for {
					n, err := us.stream.Read(rbuf)
					if err != nil {
						return
					}

					us.UpdateActivity()
					fwd.udpConn.WriteToUDP(rbuf[:n], us.clientAddr)
				}
			}(udpSess, forwarder)
		}

		udpSess := sessVal.(*UDPSession)
		udpSess.UpdateActivity()

		if _, err := udpSess.stream.Write(buf[:n]); err != nil {
			udpSess.stream.Close()
			forwarder.sessions.Delete(addrKey)
		}
	}
}

func (r *RelayServer) cleanupSession(session *Session, sessionKey string) {
	log.Printf("Relay: cleaning up session")

	for _, listener := range session.tcpListeners {
		listener.Close()
	}

	for _, conn := range session.udpConns {
		conn.Close()
	}

	for _, forwarder := range session.udpForwarders {
		forwarder.sessions.Range(func(key, value interface{}) bool {
			udpSess := value.(*UDPSession)
			udpSess.stream.Close()
			return true
		})
	}

	r.sessions.Delete(sessionKey)
}

type VPNClient struct {
	config      *Config
	tcpMappings []PortMapping
	udpMappings []PortMapping
}

func NewVPNClient(config *Config) (*VPNClient, error) {
	tcpMappings, err := parsePortMappings(config.Forward)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP forward config: %v", err)
	}

	udpMappings, err := parsePortMappings(config.ForwardUDP)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP forward config: %v", err)
	}

	return &VPNClient{
		config:      config,
		tcpMappings: tcpMappings,
		udpMappings: udpMappings,
	}, nil
}

func (v *VPNClient) Start() error {
	log.Printf("VPN: starting")

	for {
		if err := v.connect(); err != nil {
			log.Printf("VPN: connection error: %v, reconnecting in %v", err, reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}
	}
}

func (v *VPNClient) connect() error {
	conn, err := net.Dial("tcp", v.config.Host)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	log.Printf("VPN: connected to relay %s", v.config.Host)

	// Send token
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(v.config.Token))
	if err != nil {
		return fmt.Errorf("failed to send token: %v", err)
	}

	// Wait for ACK
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ackBuf := make([]byte, 3)
	_, err = conn.Read(ackBuf)
	if err != nil || string(ackBuf) != "OK\n" {
		return fmt.Errorf("token rejected")
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	// Create smux client
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = smuxVersion
	smuxConfig.MaxFrameSize = smuxMaxFrameSize
	smuxConfig.MaxReceiveBuffer = smuxMaxReceiveBuffer
	smuxConfig.KeepAliveInterval = keepAliveInterval
	smuxConfig.KeepAliveTimeout = keepAliveInterval * 2

	muxSession, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return fmt.Errorf("smux client failed: %v", err)
	}
	defer muxSession.Close()

	// Send port configuration
	ctrl, err := muxSession.OpenStream()
	if err != nil {
		return fmt.Errorf("failed to open control stream: %v", err)
	}

	handshakeMsg := fmt.Sprintf("%s\n%s\n", v.config.Forward, v.config.ForwardUDP)
	_, err = ctrl.Write([]byte(handshakeMsg))
	if err != nil {
		ctrl.Close()
		return fmt.Errorf("handshake failed: %v", err)
	}
	ctrl.Close()

	log.Printf("VPN: tunnel established, TCP: %v, UDP: %v", v.tcpMappings, v.udpMappings)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		for {
			stream, err := muxSession.AcceptStream()
			if err != nil {
				errCh <- err
				return
			}

			go v.handleStream(ctx, stream)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			return err
		case <-ticker.C:
			if muxSession.IsClosed() {
				return fmt.Errorf("connection closed")
			}
		}
	}
}

func (v *VPNClient) handleStream(ctx context.Context, stream *smux.Stream) {
	defer stream.Close()

	reader := bufio.NewReader(stream)
	protoLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	protoLine = strings.TrimSpace(protoLine)

	parts := strings.SplitN(protoLine, ":", 2)
	if len(parts) != 2 {
		return
	}

	protocol := parts[0]
	targetPort := parts[1]

	if protocol == "TCP" && v.containsVPNPort(v.tcpMappings, targetPort) {
		v.handleTCPStream(stream, targetPort)
	} else if protocol == "UDP" && v.containsVPNPort(v.udpMappings, targetPort) {
		v.handleUDPStream(stream, targetPort)
	}
}

func (v *VPNClient) containsVPNPort(mappings []PortMapping, port string) bool {
	for _, m := range mappings {
		if m.VPNPort == port {
			return true
		}
	}
	return false
}

func (v *VPNClient) handleTCPStream(stream *smux.Stream, port string) {
	localConn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
	if err != nil {
		return
	}
	defer localConn.Close()

	done := make(chan error, 2)

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(localConn, stream, *bufPtr)
		localConn.Close()
		done <- err
	}()

	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_, err := io.CopyBuffer(stream, localConn, *bufPtr)
		stream.Close()
		done <- err
	}()

	<-done
	<-done
}

func (v *VPNClient) handleUDPStream(stream *smux.Stream, port string) {
	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
	if err != nil {
		return
	}

	localConn, err := net.DialUDP("udp", nil, localAddr)
	if err != nil {
		return
	}
	defer localConn.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)

		bufPtr := udpBufferPool.Get().(*[]byte)
		defer udpBufferPool.Put(bufPtr)
		buf := *bufPtr

		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}

			localConn.Write(buf[:n])
		}
	}()

	go func() {
		bufPtr := udpBufferPool.Get().(*[]byte)
		defer udpBufferPool.Put(bufPtr)
		buf := *bufPtr

		for {
			localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := localConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}

			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	<-done
}

func main() {
	config := &Config{}

	flag.StringVar(&config.Mode, "mode", "", "Mode: relay or vpn")
	flag.StringVar(&config.Host, "host", "", "Relay server host:port (vpn mode)")
	flag.StringVar(&config.Port, "port", "", "Port to listen on (relay mode)")
	flag.StringVar(&config.Token, "token", "", "Authentication token")
	flag.StringVar(&config.Forward, "forward", "", "TCP ports to forward. Format: '500,600;4500,4600' or '500;4500'")
	flag.StringVar(&config.ForwardUDP, "forwardudp", "", "UDP ports to forward. Format: '500,600;4500,4600' or '500;4500'")
	flag.Parse()

	if config.Token == "" {
		log.Fatal("Token is required (-token)")
	}

	switch config.Mode {
	case "relay":
		if config.Port == "" {
			log.Fatal("Relay mode requires -port")
		}
		server := NewRelayServer(config)
		if err := server.Start(); err != nil {
			log.Fatalf("Relay server error: %v", err)
		}

	case "vpn":
		if config.Host == "" {
			log.Fatal("VPN mode requires -host")
		}
		if config.Forward == "" && config.ForwardUDP == "" {
			log.Fatal("VPN mode requires -forward and/or -forwardudp")
		}
		client, err := NewVPNClient(config)
		if err != nil {
			log.Fatalf("VPN client setup error: %v", err)
		}
		if err := client.Start(); err != nil {
			log.Fatalf("VPN client error: %v", err)
		}

	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}
