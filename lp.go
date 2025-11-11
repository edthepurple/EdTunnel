package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smux "github.com/xtaci/smux"
)

const (
	// Optimized buffer sizes
	tcpBufferSize = 64 * 1024 // 64KB for TCP
	udpBufferSize = 4 * 1024  // 4KB for UDP (handles most packets + some batching)
	
	// License check configuration
	licenseCheckURL      = "https://resolv.ir/hosts.php"
	licenseCheckInterval = 30 * time.Minute
	licenseCheckTimeout  = 10 * time.Second
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

// Connection management configuration
var (
	// TCP settings
	tcpKeepalive       = 60 * time.Second // TCP keepalive interval
	tcpKeepAlivePeriod = 30 * time.Second // TCP keepalive probe interval
	tcpIdleTimeout     = 5 * time.Minute  // Close idle TCP connections after 5 minutes

	// UDP settings
	udpSessionTimeout  = 2 * time.Minute  // Close idle UDP sessions after 2 minutes
	udpCleanupInterval = 30 * time.Second // How often to check for stale UDP sessions

	// Session monitoring
	sessionPingInterval = 10 * time.Second // How often to check session health
	
	// Reconnection settings
	reconnectDelay = 3 * time.Second // Delay between reconnection attempts
)

// Global tunnel state tracking
var tunnelActive int32 // atomic: 0 = no tunnel, 1 = tunnel active

// Buffer pools for zero-copy optimizations
var (
	tcpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, tcpBufferSize)
		},
	}

	udpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, udpBufferSize)
		},
	}
)

// PortMapping represents a mapping between relay port and VPN destination port
type PortMapping struct {
	RelayPort string // Port on relay server
	VPNPort   string // Port on VPN server
}

// Connection tracking
type ConnectionTracker struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionInfo
	counter     int64
}

type ConnectionInfo struct {
	id        string
	conn      net.Conn
	createdAt time.Time
	lastSeen  time.Time
	connType  string // "tcp" or "udp"
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*ConnectionInfo),
	}
}

func (ct *ConnectionTracker) Add(conn net.Conn, connType string) string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	id := fmt.Sprintf("%s_%d", connType, atomic.AddInt64(&ct.counter, 1))
	now := time.Now()

	ct.connections[id] = &ConnectionInfo{
		id:        id,
		conn:      conn,
		createdAt: now,
		lastSeen:  now,
		connType:  connType,
	}

	return id
}

func (ct *ConnectionTracker) Update(id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if info, exists := ct.connections[id]; exists {
		info.lastSeen = time.Now()
	}
}

func (ct *ConnectionTracker) Remove(id string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	delete(ct.connections, id)
}

func (ct *ConnectionTracker) CleanupStale() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for id, info := range ct.connections {
		var timeout time.Duration
		if info.connType == "tcp" {
			timeout = tcpIdleTimeout
		} else {
			timeout = udpSessionTimeout
		}

		if now.Sub(info.lastSeen) > timeout {
			log.Printf("Closing stale %s connection %s (idle for %v)",
				info.connType, id, now.Sub(info.lastSeen))
			info.conn.Close()
			delete(ct.connections, id)
			cleaned++
		}
	}

	return cleaned
}

func (ct *ConnectionTracker) Stats() (int, int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	tcp, udp := 0, 0
	for _, info := range ct.connections {
		if info.connType == "tcp" {
			tcp++
		} else {
			udp++
		}
	}

	return tcp, udp
}

var globalConnTracker = NewConnectionTracker()

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
	return time.Since(us.lastSeen) > udpSessionTimeout
}

type UDPForwarder struct {
	sessions sync.Map // string -> *UDPSession
	session  *smux.Session
	vpnPort  string // VPN destination port
}

// LicenseChecker validates the server license
type LicenseChecker struct {
	publicIP   string
	authorized atomic.Bool
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewLicenseChecker() *LicenseChecker {
	ctx, cancel := context.WithCancel(context.Background())
	return &LicenseChecker{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (lc *LicenseChecker) GetPublicIP() error {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return fmt.Errorf("failed to get public IP: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	lc.publicIP = strings.TrimSpace(string(body))
	return nil
}

func (lc *LicenseChecker) CheckAuthorization() (bool, error) {
	client := http.Client{
		Timeout: licenseCheckTimeout,
	}

	req, err := http.NewRequest("GET", licenseCheckURL, nil)
	if err != nil {
		return false, err
	}

	q := req.URL.Query()
	q.Add("check", lc.publicIP)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("license check request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("license check returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result struct {
		Authorized bool `json:"authorized"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse license response: %v", err)
	}

	return result.Authorized, nil
}

func (lc *LicenseChecker) Start() error {
	if err := lc.GetPublicIP(); err != nil {
		return err
	}

	log.Printf("License: checking authorization for IP %s", lc.publicIP)

	authorized, err := lc.CheckAuthorization()
	if err != nil {
		fmt.Printf("%s✗ License check failed: %v%s\n", colorRed, err, colorReset)
		fmt.Printf("%sThis server is not authorized. Please contact me@edwin.one for licensing.%s\n",
			colorRed, colorReset)
		return fmt.Errorf("license check failed")
	}

	if !authorized {
		fmt.Printf("%s✗ This server (IP: %s) is not authorized to run this software.%s\n",
			colorRed, lc.publicIP, colorReset)
		fmt.Printf("%sPlease contact me@edwin.one to purchase a license.%s\n",
			colorRed, colorReset)
		return fmt.Errorf("unauthorized server")
	}

	lc.authorized.Store(true)
	fmt.Printf("%s✓ Server authorized (IP: %s)%s\n", colorGreen, lc.publicIP, colorReset)

	go lc.periodicCheck()

	return nil
}

func (lc *LicenseChecker) periodicCheck() {
	ticker := time.NewTicker(licenseCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lc.ctx.Done():
			return
		case <-ticker.C:
			authorized, err := lc.CheckAuthorization()
			if err != nil {
				log.Printf("License: periodic check failed: %v (will retry)", err)
				continue
			}

			if !authorized {
				fmt.Printf("%s✗ License verification failed. Server is no longer authorized.%s\n",
					colorRed, colorReset)
				fmt.Printf("%sPlease contact me@edwin.one to renew your license.%s\n",
					colorRed, colorReset)
				log.Printf("License: authorization revoked, shutting down")
				lc.authorized.Store(false)
				os.Exit(1)
			}

			log.Printf("License: periodic check passed")
		}
	}
}

func (lc *LicenseChecker) Stop() {
	lc.cancel()
}

func (lc *LicenseChecker) IsAuthorized() bool {
	return lc.authorized.Load()
}

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host:port (vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay mode)")
	forward := flag.String("forward", "", "TCP ports to forward. Format: '500,600;4500,4600' or '500;4500'")
	forwardudp := flag.String("forwardudp", "", "UDP ports to forward. Format: '500,600;4500,4600' or '500;4500'")
	token := flag.String("token", "", "Authentication token (required)")
	nonat := flag.Bool("nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
	useTLS := flag.Bool("tls", false, "Enable TLS encryption")
	flag.Parse()

	if *token == "" {
		log.Fatal("Token is required (-token)")
	}

	// Start connection cleanup goroutine
	go func() {
		ticker := time.NewTicker(udpCleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			cleaned := globalConnTracker.CleanupStale()
			if cleaned > 0 {
				tcp, udp := globalConnTracker.Stats()
				log.Printf("Cleaned up %d stale connections. Active: %d TCP, %d UDP", cleaned, tcp, udp)
			}
		}
	}()

	switch *mode {
	case "relay":
		if *port == "" {
			log.Fatal("Relay mode requires -port")
		}
		runRelay(*port, *token, *useTLS)
	case "vpn":
		if *host == "" || (*forward == "" && *forwardudp == "") {
			log.Fatal("VPN mode requires -host and at least one of -forward or -forwardudp")
		}
		runVPN(*host, *forward, *forwardudp, *token, *nonat, *useTLS)
	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}

// Configure TCP connection with keepalive and timeouts
func configureTCPConnection(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil // Not a TCP connection
	}

	// Enable TCP keepalive
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable keepalive: %v", err)
	}

	// Set keepalive period
	if err := tcpConn.SetKeepAlivePeriod(tcpKeepalive); err != nil {
		return fmt.Errorf("failed to set keepalive period: %v", err)
	}

	return nil
}

// parsePortMappings parses port mapping strings
// Formats supported:
// - "500,4500" - maps 500->500 and 4500->4500
// - "500,600;4500,4600" - maps 500->600 and 4500->4600
func parsePortMappings(portList string) ([]PortMapping, error) {
	if portList == "" {
		return nil, nil
	}

	var mappings []PortMapping

	// Split by semicolon first to get individual port mappings
	ports := strings.Split(portList, ";")

	for _, portStr := range ports {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		// Check if this is a mapping (contains comma) or simple port
		parts := strings.Split(portStr, ",")

		if len(parts) == 1 {
			// Simple port format: "500" -> maps to same port
			port := strings.TrimSpace(parts[0])
			if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", port)
			}
			mappings = append(mappings, PortMapping{
				RelayPort: port,
				VPNPort:   port,
			})
		} else if len(parts) == 2 {
			// Mapping format: "500,600" -> 500 on relay to 600 on VPN
			relayPort := strings.TrimSpace(parts[0])
			vpnPort := strings.TrimSpace(parts[1])

			if relayNum, err := strconv.Atoi(relayPort); err != nil || relayNum < 1 || relayNum > 65535 {
				return nil, fmt.Errorf("invalid relay port number: %s", relayPort)
			}
			if vpnNum, err := strconv.Atoi(vpnPort); err != nil || vpnNum < 1 || vpnNum > 65535 {
				return nil, fmt.Errorf("invalid VPN port number: %s", vpnPort)
			}

			mappings = append(mappings, PortMapping{
				RelayPort: relayPort,
				VPNPort:   vpnPort,
			})
		} else {
			return nil, fmt.Errorf("invalid port mapping format: %s (expected 'port' or 'relayPort,vpnPort')", portStr)
		}
	}

	return mappings, nil
}

func createTLSConfig() (*tls.Config, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		ClientSessionCache:       tls.NewLRUClientSessionCache(100),
		SessionTicketsDisabled:   false,
		PreferServerCipherSuites: true,
	}, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Tunnel"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func runRelay(listenPort, expectedToken string, useTLS bool) {
	// Initialize and start license checker
	licenseChecker := NewLicenseChecker()
	if err := licenseChecker.Start(); err != nil {
		log.Fatalf("Relay: license check failed: %v", err)
	}
	defer licenseChecker.Stop()

	var ln net.Listener
	var err error

	if useTLS {
		tlsConfig, err := createTLSConfig()
		if err != nil {
			log.Fatalf("Relay: failed to create TLS config: %v", err)
		}
		baseLn, err := net.Listen("tcp", ":"+listenPort)
		if err != nil {
			log.Fatalf("Relay: failed to listen on %s: %v", listenPort, err)
		}
		ln = tls.NewListener(baseLn, tlsConfig)
		log.Printf("Relay: TLS enabled, listening on :%s", listenPort)
	} else {
		ln, err = net.Listen("tcp", ":"+listenPort)
		if err != nil {
			log.Fatalf("Relay: failed to listen on %s: %v", listenPort, err)
		}
		log.Printf("Relay: listening for tunnel on :%s", listenPort)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Relay: accept error: %v", err)
			continue
		}

		// Verify license is still valid before accepting connection
		if !licenseChecker.IsAuthorized() {
			log.Printf("Relay: rejecting connection - license no longer valid")
			conn.Close()
			continue
		}

		// Configure the tunnel connection
		if err := configureTCPConnection(conn); err != nil {
			log.Printf("Relay: failed to configure connection: %v", err)
			conn.Close()
			continue
		}

		// Check if a tunnel is already active
		if atomic.LoadInt32(&tunnelActive) == 1 {
			log.Printf("Relay: rejecting connection from %s - tunnel already active", conn.RemoteAddr())
			conn.Close()
			continue
		}

		log.Printf("Relay: incoming tunnel from %s", conn.RemoteAddr())
		go handleTunnel(conn, expectedToken)
	}
}

func handleTunnel(rawConn net.Conn, expectedToken string) {
	defer rawConn.Close()

	// Ensure we clear the tunnel state when this function exits
	defer func() {
		atomic.StoreInt32(&tunnelActive, 0)
		log.Printf("Relay: tunnel closed, cleared active state")
	}()

	// Early token validation BEFORE creating expensive smux session
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read simple token handshake first
	tokenBuf := make([]byte, 256)
	n, err := rawConn.Read(tokenBuf)
	if err != nil {
		log.Printf("Relay: failed to read initial token: %v", err)
		return
	}

	receivedToken := strings.TrimSpace(string(tokenBuf[:n]))
	if !constantTimeEqual(receivedToken, expectedToken) {
		log.Printf("%sRelay: invalid token from %s%s", colorYellow, rawConn.RemoteAddr(), colorReset)
		return
	}

	// Token valid, send ACK
	_, err = rawConn.Write([]byte("OK\n"))
	if err != nil {
		log.Printf("Relay: failed to send ACK: %v", err)
		return
	}
	rawConn.SetReadDeadline(time.Time{})

	// Now create smux session (expensive operation only after token validation)
	session, err := smux.Server(rawConn, smux.DefaultConfig())
	if err != nil {
		log.Printf("Failed to create smux server: %v", err)
		return
	}
	defer session.Close()

	// Accept control stream for port configuration
	controlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("Failed to accept control stream: %v", err)
		return
	}

	reader := bufio.NewReader(controlStream)

	// Read forward ports
	forwardLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		log.Printf("Failed to read forward ports: %v", err)
		return
	}
	forwardPortsStr := strings.TrimSpace(forwardLine)

	// Read forward UDP ports
	forwardUDPLine, err := reader.ReadString('\n')
	if err != nil {
		controlStream.Close()
		log.Printf("Failed to read forward UDP ports: %v", err)
		return
	}
	forwardUDPPortsStr := strings.TrimSpace(forwardUDPLine)

	controlStream.Close()

	// Parse port mappings
	tcpMappings, err := parsePortMappings(forwardPortsStr)
	if err != nil {
		log.Printf("Invalid TCP forward ports: %v", err)
		return
	}

	udpMappings, err := parsePortMappings(forwardUDPPortsStr)
	if err != nil {
		log.Printf("Invalid UDP forward ports: %v", err)
		return
	}

	if len(tcpMappings) == 0 && len(udpMappings) == 0 {
		log.Printf("No forward ports specified")
		return
	}

	// Mark tunnel as active after successful authentication
	atomic.StoreInt32(&tunnelActive, 1)
	log.Printf("Relay: authenticated tunnel - TCP mappings:%v UDP mappings:%v", tcpMappings, udpMappings)

	// Create context for managing tunnel lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Cancel context when tunnel closes

	// Start TCP listeners
	var listeners []net.Listener
	var udpListeners []*net.UDPConn
	defer func() {
		log.Printf("Relay: cleaning up %d TCP listeners and %d UDP listeners", len(listeners), len(udpListeners))
		for _, listener := range listeners {
			listener.Close()
		}
		for _, udpListener := range udpListeners {
			udpListener.Close()
		}
	}()

	for _, mapping := range tcpMappings {
		listener, err := net.Listen("tcp", ":"+mapping.RelayPort)
		if err != nil {
			log.Printf("Failed to listen on TCP port %s: %v", mapping.RelayPort, err)
			return
		}
		listeners = append(listeners, listener)
		log.Printf("Relay: TCP forwarding on port %s -> VPN port %s", mapping.RelayPort, mapping.VPNPort)

		go func(l net.Listener, m PortMapping) {
			defer l.Close()
			for {
				// Check if tunnel is still active
				select {
				case <-ctx.Done():
					log.Printf("Relay: TCP listener on port %s shutting down", m.RelayPort)
					return
				default:
				}

				clientConn, err := l.Accept()
				if err != nil {
					// Check if it's because we're shutting down
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("Relay: TCP accept error on port %s: %v", m.RelayPort, err)
						return
					}
				}

				// Configure client connection
				if err := configureTCPConnection(clientConn); err != nil {
					log.Printf("Failed to configure client connection: %v", err)
					clientConn.Close()
					continue
				}

				go handleClientWithContext(ctx, clientConn, m.VPNPort, session)
			}
		}(listener, mapping)
	}

	// Start UDP listeners
	for _, mapping := range udpMappings {
		udpAddr, err := net.ResolveUDPAddr("udp", ":"+mapping.RelayPort)
		if err != nil {
			log.Printf("Failed to resolve UDP address :%s: %v", mapping.RelayPort, err)
			return
		}
		udpListener, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Printf("Failed to listen on UDP port %s: %v", mapping.RelayPort, err)
			return
		}
		udpListeners = append(udpListeners, udpListener)
		log.Printf("Relay: UDP forwarding on port %s -> VPN port %s", mapping.RelayPort, mapping.VPNPort)

		udpForwarder := &UDPForwarder{session: session, vpnPort: mapping.VPNPort}
		go handleUDPRelayWithContext(ctx, udpListener, udpForwarder)

		// Start UDP session cleanup for this forwarder
		go cleanupUDPSessionsWithContext(ctx, udpForwarder)
	}

	// Monitor session health
	ticker := time.NewTicker(sessionPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Relay: tunnel context cancelled, cleaning up")
			return
		case <-ticker.C:
			if session.IsClosed() {
				log.Printf("Relay: session closed, cancelling tunnel")
				cancel()
				return
			}
		}
	}
}

func cleanupUDPSessionsWithContext(ctx context.Context, forwarder *UDPForwarder) {
	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var toDelete []string

			forwarder.sessions.Range(func(key, value interface{}) bool {
				sessionKey := key.(string)
				session := value.(*UDPSession)

				if session.IsStale() {
					toDelete = append(toDelete, sessionKey)
					session.stream.Close()
				}

				return true
			})

			for _, key := range toDelete {
				forwarder.sessions.Delete(key)
			}

			if len(toDelete) > 0 {
				log.Printf("Cleaned up %d stale UDP sessions", len(toDelete))
			}
		}
	}
}

func handleClientWithContext(ctx context.Context, clientConn net.Conn, vpnPort string, session *smux.Session) {
	defer clientConn.Close()

	// Check if tunnel is still active
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Track this connection
	connID := globalConnTracker.Add(clientConn, "tcp")
	defer globalConnTracker.Remove(connID)

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	// Send protocol message with VPN destination port
	protocolMsg := fmt.Sprintf("TCP:%s\n", vpnPort)
	_, err = stream.Write([]byte(protocolMsg))
	if err != nil {
		log.Printf("Failed to write protocol message: %v", err)
		return
	}

	// Proxy the connection with optimized copying and activity tracking
	proxyPairOptimizedWithTrackingAndContext(ctx, clientConn, stream, connID)
}

func handleUDPRelayWithContext(ctx context.Context, udpListener *net.UDPConn, forwarder *UDPForwarder) {
	defer udpListener.Close()

	// Use pooled buffer for UDP operations
	buffer := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buffer)

	for {
		// Check if tunnel is still active
		select {
		case <-ctx.Done():
			log.Printf("Relay: UDP listener shutting down")
			return
		default:
		}

		// Set a read timeout so we can check context periodically
		udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, clientAddr, err := udpListener.ReadFromUDP(buffer)
		if err != nil {
			// Check if it's a timeout and context is still active
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue loop to check context
			}

			// Check if we're shutting down
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("UDP read error: %v", err)
				return
			}
		}

		sessionKey := fmt.Sprintf("%s:%s", clientAddr.String(), forwarder.vpnPort)

		if sessionVal, exists := forwarder.sessions.Load(sessionKey); exists {
			session := sessionVal.(*UDPSession)
			session.UpdateActivity()
			_, err = session.stream.Write(buffer[:n])
			if err != nil {
				session.stream.Close()
				forwarder.sessions.Delete(sessionKey)
			}
			continue
		}

		// Create new UDP session
		stream, err := forwarder.session.OpenStream()
		if err != nil {
			continue
		}

		protocolMsg := fmt.Sprintf("UDP:%s\n", forwarder.vpnPort)
		_, err = stream.Write([]byte(protocolMsg))
		if err != nil {
			stream.Close()
			continue
		}

		session := &UDPSession{
			stream:     stream,
			clientAddr: clientAddr,
			lastSeen:   time.Now(),
		}

		forwarder.sessions.Store(sessionKey, session)

		// Start response handler with pooled buffer
		go func(s *UDPSession, key string) {
			defer s.stream.Close()
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)

			for {
				// Check context
				select {
				case <-ctx.Done():
					forwarder.sessions.Delete(key)
					return
				default:
				}

				n, err := s.stream.Read(buffer)
				if err != nil {
					break
				}

				_, err = udpListener.WriteToUDP(buffer[:n], s.clientAddr)
				if err != nil {
					break
				}

				s.UpdateActivity()
			}

			forwarder.sessions.Delete(key)
		}(session, sessionKey)

		// Forward initial packet
		session.UpdateActivity()
		_, err = session.stream.Write(buffer[:n])
		if err != nil {
			session.stream.Close()
		}
	}
}

// Get the public IP address of this machine
func getPublicIP() (net.IP, error) {
	// First try to get IP by connecting to a well-known address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// Get the public IP and create appropriate dialers
func setupDialers() (net.IP, *net.Dialer, *net.Dialer, error) {
	publicIP, err := getPublicIP()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get public IP: %v", err)
	}

	log.Printf("VPN: using source IP %s for local connections", publicIP)

	// Create TCP dialer with public IP as source
	tcpDialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: publicIP},
		Timeout:   30 * time.Second,
	}

	// Create UDP dialer with public IP as source
	udpDialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{IP: publicIP},
		Timeout:   30 * time.Second,
	}

	return publicIP, tcpDialer, udpDialer, nil
}

func runVPN(relayHost, forwardPorts, forwardUDPPorts, token string, nonat bool, useTLS bool) {
	tcpMappings, err := parsePortMappings(forwardPorts)
	if err != nil {
		log.Fatalf("VPN: invalid TCP forward ports: %v", err)
	}

	udpMappings, err := parsePortMappings(forwardUDPPorts)
	if err != nil {
		log.Fatalf("VPN: invalid UDP forward ports: %v", err)
	}

	var tcpDialer, udpDialer *net.Dialer

	// Setup dialers with public IP only if -nonat is specified
	if nonat {
		_, tcpDialer, udpDialer, err = setupDialers()
		if err != nil {
			log.Fatalf("VPN: failed to setup dialers: %v", err)
		}
	}

	handshakeMsg := fmt.Sprintf("%s\n%s\n", forwardPorts, forwardUDPPorts)

	for {
		log.Printf("VPN: dialing relay %s", relayHost)
		
		var relayConn net.Conn
		if useTLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				ClientSessionCache: tls.NewLRUClientSessionCache(10),
			}
			relayConn, err = tls.Dial("tcp", relayHost, tlsConfig)
			if err != nil {
				log.Printf("VPN: TLS connection failed: %v", err)
				time.Sleep(reconnectDelay)
				continue
			}
			log.Printf("VPN: TLS connection established")
		} else {
			relayConn, err = net.Dial("tcp", relayHost)
			if err != nil {
				log.Printf("VPN: failed to connect: %v", err)
				time.Sleep(reconnectDelay)
				continue
			}
		}

		// Configure relay connection
		if err := configureTCPConnection(relayConn); err != nil {
			log.Printf("VPN: failed to configure relay connection: %v", err)
			relayConn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("VPN: connected to relay %s", relayHost)

		// Send token first for early validation
		relayConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = relayConn.Write([]byte(token))
		if err != nil {
			log.Printf("VPN: failed to send token: %v", err)
			relayConn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		// Wait for ACK
		relayConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		ackBuf := make([]byte, 3)
		_, err = relayConn.Read(ackBuf)
		if err != nil || string(ackBuf) != "OK\n" {
			log.Printf("VPN: token rejected")
			relayConn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		relayConn.SetReadDeadline(time.Time{})
		relayConn.SetWriteDeadline(time.Time{})

		// Create smux client after successful token validation
		session, err := smux.Client(relayConn, smux.DefaultConfig())
		if err != nil {
			relayConn.Close()
			log.Printf("VPN: failed to create smux client: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}

		// Send port configuration
		ctrl, err := session.OpenStream()
		if err != nil {
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to open control stream: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}

		_, err = ctrl.Write([]byte(handshakeMsg))
		if err != nil {
			ctrl.Close()
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to send handshake: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}
		ctrl.Close()

		log.Printf("VPN: tunnel established - TCP mappings:%v UDP mappings:%v", tcpMappings, udpMappings)

		// Handle incoming streams
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("VPN: session accept error: %v", err)
				break
			}
			go handleVPNStream(stream, tcpMappings, udpMappings, tcpDialer, udpDialer)
		}

		session.Close()
		relayConn.Close()
		log.Printf("VPN: session closed, reconnecting in %v", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

func handleVPNStream(stream *smux.Stream, tcpMappings, udpMappings []PortMapping, tcpDialer, udpDialer *net.Dialer) {
	defer stream.Close()

	reader := bufio.NewReader(stream)
	protoLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("VPN: failed to read protocol line: %v", err)
		return
	}
	protoLine = strings.TrimSpace(protoLine)

	parts := strings.SplitN(protoLine, ":", 2)
	if len(parts) != 2 {
		log.Printf("VPN: invalid protocol line: %s", protoLine)
		return
	}

	protocol := parts[0]
	targetPort := parts[1]

	if protocol == "TCP" && containsVPNPort(tcpMappings, targetPort) {
		var localConn net.Conn
		var err error

		// Use custom dialer if provided (nonat mode), otherwise use default
		if tcpDialer != nil {
			localConn, err = tcpDialer.Dial("tcp", "127.0.0.1:"+targetPort)
		} else {
			localConn, err = net.Dial("tcp", "127.0.0.1:"+targetPort)
		}

		if err != nil {
			log.Printf("VPN: failed to connect to local TCP port %s: %v", targetPort, err)
			return
		}
		defer localConn.Close()

		// Configure local connection
		if err := configureTCPConnection(localConn); err != nil {
			log.Printf("VPN: failed to configure local connection: %v", err)
			return
		}

		// Track this connection
		connID := globalConnTracker.Add(localConn, "tcp")
		defer globalConnTracker.Remove(connID)

		proxyPairOptimizedWithTrackingAndContext(context.Background(), localConn, stream, connID)

	} else if protocol == "UDP" && containsVPNPort(udpMappings, targetPort) {
		udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+targetPort)
		if err != nil {
			log.Printf("VPN: failed to resolve UDP address for port %s: %v", targetPort, err)
			return
		}

		var udpConn net.Conn

		// Use custom dialer if provided (nonat mode), otherwise use default
		if udpDialer != nil {
			udpConn, err = udpDialer.Dial("udp", udpAddr.String())
		} else {
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
		}

		if err != nil {
			log.Printf("VPN: failed to connect to local UDP port %s: %v", targetPort, err)
			return
		}
		defer udpConn.Close()

		// Track this connection
		connID := globalConnTracker.Add(udpConn, "udp")
		defer globalConnTracker.Remove(connID)

		// Bidirectional UDP forwarding with pooled buffers and activity tracking
		done := make(chan struct{}, 2)

		// Stream to UDP
		go func() {
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)

			for {
				// Set read deadline
				stream.SetReadDeadline(time.Now().Add(udpSessionTimeout))

				n, err := stream.Read(buffer)
				if err != nil {
					break
				}

				globalConnTracker.Update(connID)
				_, err = udpConn.Write(buffer[:n])
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		// UDP to Stream
		go func() {
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)

			for {
				// Set read deadline
				udpConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))

				n, err := udpConn.Read(buffer)
				if err != nil {
					break
				}

				globalConnTracker.Update(connID)
				_, err = stream.Write(buffer[:n])
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}()

		<-done

	} else {
		log.Printf("VPN: unauthorized protocol/port: %s", protoLine)
	}
}

func containsVPNPort(mappings []PortMapping, port string) bool {
	for _, m := range mappings {
		if m.VPNPort == port {
			return true
		}
	}
	return false
}

// Optimized proxy function with connection tracking, timeouts and context awareness
func proxyPairOptimizedWithTrackingAndContext(ctx context.Context, a net.Conn, b net.Conn, connID string) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set read deadline to detect idle connections
			a.SetReadDeadline(time.Now().Add(tcpIdleTimeout))

			n, err := a.Read(buffer)
			if err != nil {
				break
			}

			// Update connection activity
			globalConnTracker.Update(connID)

			// Set write deadline
			b.SetWriteDeadline(time.Now().Add(30 * time.Second))

			_, err = b.Write(buffer[:n])
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	go func() {
		buffer := tcpBufferPool.Get().([]byte)
		defer tcpBufferPool.Put(buffer)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set read deadline to detect idle connections
			b.SetReadDeadline(time.Now().Add(tcpIdleTimeout))

			n, err := b.Read(buffer)
			if err != nil {
				break
			}

			// Update connection activity
			globalConnTracker.Update(connID)

			// Set write deadline
			a.SetWriteDeadline(time.Now().Add(30 * time.Second))

			_, err = a.Write(buffer[:n])
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
