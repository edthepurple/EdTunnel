// +build linux

package main

import (
        "bufio"
        "context"
        "crypto/rand"
        "crypto/rsa"
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
        "runtime"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"

        "github.com/xtaci/smux"
        "golang.org/x/sys/unix"
)

// ANSI color codes
const (
        colorReset  = "\033[0m"
        colorRed    = "\033[31m"
        colorGreen  = "\033[32m"
        colorYellow = "\033[33m"
)

// License check configuration
const (
        licenseCheckURL      = "https://resolv.ir/hosts.php"
        licenseCheckInterval = 30 * time.Minute
        licenseCheckTimeout  = 10 * time.Second
)

// Configuration constants
const (
        // Protocol constants
        protocolVersion = byte(1)

        // Configuration - optimized for maximum throughput
        bufferSize       = 128 * 1024 // 128KB buffers for high throughput
        udpBufferSize    = 65535      // Max UDP packet size
        idleTimeout      = 5 * time.Minute
        reconnectDelay   = 3 * time.Second
        keepAliveInterval = 30 * time.Second

        // TCP tuning for maximum throughput
        tcpReadBuffer  = 4 * 1024 * 1024  // 4MB
        tcpWriteBuffer = 4 * 1024 * 1024  // 4MB

        // smux configuration for maximum performance and lower latency
        smuxVersion          = 1
        smuxMaxFrameSize     = 16384        // 16KB frames
        smuxMaxReceiveBuffer = 4194304      // 4MB receive buffer

        // Port scanning protection
        maxConnectionsPerIP     = 5              // Max concurrent connections per IP
        connectionAttemptWindow = 1 * time.Minute // Time window for tracking attempts
        maxAttemptsPerWindow    = 10             // Max connection attempts per window
        blockDuration           = 15 * time.Minute // How long to block suspicious IPs
        cleanupInterval         = 5 * time.Minute  // How often to clean up old entries
)

// PortMapping represents a mapping between relay port and VPN destination port
type PortMapping struct {
        RelayPort string // Port on relay server
        VPNPort   string // Port on VPN server
}

// Buffer pools
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

func init() {
        runtime.GOMAXPROCS(runtime.NumCPU())
        log.Printf("System: GOMAXPROCS set to %d cores", runtime.NumCPU())
}

// Pin current goroutine/thread to specific CPU core
func pinToCPU(cpu int) error {
        runtime.LockOSThread()

        var cpuSet unix.CPUSet
        cpuSet.Set(cpu)

        return unix.SchedSetaffinity(0, &cpuSet)
}

// Anti-bufferbloat: Enhanced TCP tuning with BBR if available
func tuneTCPConn(conn net.Conn) error {
        tcpConn, ok := conn.(*net.TCPConn)
        if !ok {
                return nil
        }

        // Disable Nagle's algorithm for lower latency
        if err := tcpConn.SetNoDelay(true); err != nil {
                return err
        }

        // Set moderate buffers to avoid bufferbloat
        if err := tcpConn.SetReadBuffer(tcpReadBuffer); err != nil {
                return err
        }
        if err := tcpConn.SetWriteBuffer(tcpWriteBuffer); err != nil {
                return err
        }

        // Enable TCP keepalive
        if err := tcpConn.SetKeepAlive(true); err != nil {
                return err
        }
        if err := tcpConn.SetKeepAlivePeriod(keepAliveInterval); err != nil {
                return err
        }

        // Advanced TCP socket options
        rawConn, err := tcpConn.SyscallConn()
        if err != nil {
                return err
        }

        var sockErr error
        err = rawConn.Control(func(fd uintptr) {
                // Disable delayed ACKs
                sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
                if sockErr != nil {
                        log.Printf("TCP: failed to set TCP_QUICKACK: %v", sockErr)
                        return
                }

                // Ensure TCP_CORK is disabled
                sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, 0)
                if sockErr != nil {
                        log.Printf("TCP: failed to disable TCP_CORK: %v", sockErr)
                        return
                }

                // Try to enable BBR congestion control (Linux 4.9+)
                sockErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
                if sockErr != nil {
                        // Fall back to cubic if BBR not available
                        log.Printf("TCP: BBR not available, using default congestion control")
                        sockErr = nil
                } else {
                        log.Printf("TCP: BBR congestion control enabled")
                }

                // Set high priority for packets
                sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY, 6)
                if sockErr != nil {
                        sockErr = nil // Non-fatal
                }
        })

        if err != nil {
                return err
        }
        return sockErr
}

type Config struct {
        Mode       string
        Host       string
        Port       string
        Token      string
        Forward    string
        ForwardUDP string
        NoNAT      bool
        TLS        bool
}

// ConnectionTracker tracks connection attempts for port scan protection
type ConnectionTracker struct {
        attempts      sync.Map // map[string]*IPAttempts
        blocked       sync.Map // map[string]time.Time (IP -> block expiry)
        activeConns   sync.Map // map[string]int32 (IP -> count)
        mu            sync.RWMutex
}

type IPAttempts struct {
        count      atomic.Int32
        firstSeen  time.Time
        mu         sync.Mutex
}

func NewConnectionTracker() *ConnectionTracker {
        ct := &ConnectionTracker{}
        go ct.cleanupLoop()
        return ct
}

func (ct *ConnectionTracker) cleanupLoop() {
        ticker := time.NewTicker(cleanupInterval)
        defer ticker.Stop()

        for range ticker.C {
                now := time.Now()

                // Clean up old attempt records
                ct.attempts.Range(func(key, value interface{}) bool {
                        ip := key.(string)
                        attempts := value.(*IPAttempts)

                        attempts.mu.Lock()
                        if now.Sub(attempts.firstSeen) > connectionAttemptWindow {
                                ct.attempts.Delete(ip)
                        }
                        attempts.mu.Unlock()
                        return true
                })

                // Clean up expired blocks
                ct.blocked.Range(func(key, value interface{}) bool {
                        ip := key.(string)
                        expiry := value.(time.Time)

                        if now.After(expiry) {
                                ct.blocked.Delete(ip)
                                log.Printf("Security: unblocked IP %s", ip)
                        }
                        return true
                })
        }
}

func (ct *ConnectionTracker) recordAttempt(ip string) bool {
        // Check if IP is currently blocked
        if expiry, blocked := ct.blocked.Load(ip); blocked {
                if time.Now().Before(expiry.(time.Time)) {
                        return false
                }
                ct.blocked.Delete(ip)
        }

        now := time.Now()

        // Get or create IP attempts record
        attemptsVal, _ := ct.attempts.LoadOrStore(ip, &IPAttempts{firstSeen: now})
        attempts := attemptsVal.(*IPAttempts)

        attempts.mu.Lock()
        defer attempts.mu.Unlock()

        // Reset if window expired
        if now.Sub(attempts.firstSeen) > connectionAttemptWindow {
                attempts.count.Store(0)
                attempts.firstSeen = now
        }

        currentCount := attempts.count.Add(1)

        // Block if exceeded max attempts
        if currentCount > int32(maxAttemptsPerWindow) {
                blockUntil := now.Add(blockDuration)
                ct.blocked.Store(ip, blockUntil)
                log.Printf("Security: blocked IP %s for %v (excessive connection attempts)", ip, blockDuration)
                return false
        }

        return true
}

func (ct *ConnectionTracker) canConnect(ip string) bool {
        // Check active connections
        activeVal, exists := ct.activeConns.Load(ip)
        if !exists {
                return true
        }

        activeCount := activeVal.(int32)
        if activeCount >= int32(maxConnectionsPerIP) {
                log.Printf("Security: rejected connection from %s (max concurrent connections reached)", ip)
                return false
        }

        return true
}

func (ct *ConnectionTracker) incrementActive(ip string) {
        for {
                val, _ := ct.activeConns.LoadOrStore(ip, int32(0))
                current := val.(int32)
                if ct.activeConns.CompareAndSwap(ip, current, current+1) {
                        break
                }
        }
}

func (ct *ConnectionTracker) decrementActive(ip string) {
        if val, exists := ct.activeConns.Load(ip); exists {
                current := val.(int32)
                if current <= 1 {
                        ct.activeConns.Delete(ip)
                } else {
                        ct.activeConns.Store(ip, current-1)
                }
        }
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

func getPublicIP() (net.IP, error) {
        conn, err := net.Dial("udp", "8.8.8.8:80")
        if err != nil {
                return nil, err
        }
        defer conn.Close()

        localAddr := conn.LocalAddr().(*net.UDPAddr)
        return localAddr.IP, nil
}

func setupDialers() (net.IP, *net.Dialer, *net.Dialer, error) {
        publicIP, err := getPublicIP()
        if err != nil {
                return nil, nil, nil, fmt.Errorf("failed to get public IP: %v", err)
        }

        log.Printf("VPN: using source IP %s for local connections", publicIP)

        tcpDialer := &net.Dialer{
                LocalAddr: &net.TCPAddr{IP: publicIP},
                Timeout:   30 * time.Second,
        }

        udpDialer := &net.Dialer{
                LocalAddr: &net.UDPAddr{IP: publicIP},
                Timeout:   30 * time.Second,
        }

        return publicIP, tcpDialer, udpDialer, nil
}

func listenWithReusePort(network, address string) (net.Listener, error) {
        lc := net.ListenConfig{
                Control: func(network, address string, c syscall.RawConn) error {
                        var opErr error
                        err := c.Control(func(fd uintptr) {
                                opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET,
                                        unix.SO_REUSEPORT, 1)
                        })
                        if err != nil {
                                return err
                        }
                        return opErr
                },
        }
        return lc.Listen(context.Background(), network, address)
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
                ClientSessionCache: tls.NewLRUClientSessionCache(100),
                SessionTicketsDisabled: false,
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

// RelayServer handles incoming tunnel connections
type RelayServer struct {
        config    *Config
        sessions  sync.Map
        mu        sync.Mutex
        license   *LicenseChecker
        cpuCore   atomic.Int32
        connTracker *ConnectionTracker // Port scan protection
}

type Session struct {
        muxSession *smux.Session
        tcpMappings []PortMapping
        udpMappings []PortMapping
        token      string
        ctx        context.Context
        cancel     context.CancelFunc
        tcpListeners []net.Listener
        udpConns    []*net.UDPConn
        udpForwarders []*UDPForwarder
        lastActive atomic.Int64
}

type UDPForwarder struct {
        sessions sync.Map
        session  *smux.Session
        vpnPort  string // VPN destination port
        relayPort string // Relay listening port
        udpConn  *net.UDPConn
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
                config:      config,
                license:     NewLicenseChecker(),
                connTracker: NewConnectionTracker(),
        }
}

func (r *RelayServer) Start() error {
        if err := r.license.Start(); err != nil {
                return err
        }

        var listener net.Listener
        var err error

        if r.config.TLS {
                tlsConfig, err := createTLSConfig()
                if err != nil {
                        return fmt.Errorf("failed to create TLS config: %v", err)
                }
                baseListener, err := listenWithReusePort("tcp", ":"+r.config.Port)
                if err != nil {
                        return fmt.Errorf("failed to start listener with SO_REUSEPORT: %v", err)
                }
                listener = tls.NewListener(baseListener, tlsConfig)
                log.Printf("Relay: TLS enabled with SO_REUSEPORT")
        } else {
                listener, err = listenWithReusePort("tcp", ":"+r.config.Port)
                if err != nil {
                        return fmt.Errorf("failed to listen with SO_REUSEPORT: %v", err)
                }
                log.Printf("Relay: TCP listener with SO_REUSEPORT enabled")
        }
        defer listener.Close()

        log.Printf("Relay: listening on port %s", r.config.Port)
        log.Printf("Relay: BBR congestion control enabled (if available)")
        log.Printf("Relay: port scan protection enabled (rate limiting, connection tracking)")

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
        ip := strings.Split(remoteAddr, ":")[0]

        // Port scan protection: Check if IP is allowed to connect
        if !r.connTracker.recordAttempt(ip) {
                conn.Close()
                return
        }

        if !r.connTracker.canConnect(ip) {
                conn.Close()
                return
        }

        r.connTracker.incrementActive(ip)
        defer r.connTracker.decrementActive(ip)
        defer conn.Close()

        // Pin to CPU core
        cpuCore := int(r.cpuCore.Add(1) % int32(runtime.NumCPU()))
        if err := pinToCPU(cpuCore); err != nil {
                log.Printf("Relay: failed to pin to CPU %d: %v", cpuCore, err)
        }

        // Tune TCP connection
        if err := tuneTCPConn(conn); err != nil {
                log.Printf("Relay: failed to tune TCP connection from %s: %v", remoteAddr, err)
        }

        // Early token validation BEFORE creating expensive smux session
        conn.SetReadDeadline(time.Now().Add(5 * time.Second))

        // Read simple token handshake first
        tokenBuf := make([]byte, 256)
        n, err := conn.Read(tokenBuf)
        if err != nil {
                log.Printf("Relay: failed to read initial token from %s: %v", remoteAddr, err)
                return
        }

        receivedToken := strings.TrimSpace(string(tokenBuf[:n]))
        if receivedToken != r.config.Token {
                log.Printf("%sSecurity: invalid token from %s%s", colorYellow, remoteAddr, colorReset)
                return
        }

        // Token valid, send ACK
        conn.Write([]byte("OK\n"))
        conn.SetReadDeadline(time.Time{})

        // Now create smux session (expensive operation only after token validation)
        smuxConfig := smux.DefaultConfig()
        smuxConfig.Version = smuxVersion
        smuxConfig.MaxFrameSize = smuxMaxFrameSize
        smuxConfig.MaxReceiveBuffer = smuxMaxReceiveBuffer
        smuxConfig.KeepAliveInterval = keepAliveInterval
        smuxConfig.KeepAliveTimeout = keepAliveInterval * 2

        muxSession, err := smux.Server(conn, smuxConfig)
        if err != nil {
                log.Printf("Relay: failed to create smux session from %s: %v", remoteAddr, err)
                return
        }
        defer muxSession.Close()

        // Accept control stream for port configuration
        controlStream, err := muxSession.AcceptStream()
        if err != nil {
                log.Printf("Relay: failed to accept control stream from %s: %v", remoteAddr, err)
                return
        }

        reader := bufio.NewReader(controlStream)

        // Read forward ports
        forwardLine, err := reader.ReadString('\n')
        if err != nil {
                controlStream.Close()
                log.Printf("Relay: failed to read forward ports: %v", err)
                return
        }
        forwardPortsStr := strings.TrimSpace(forwardLine)

        // Read forward UDP ports
        forwardUDPLine, err := reader.ReadString('\n')
        if err != nil {
                controlStream.Close()
                log.Printf("Relay: failed to read forward UDP ports: %v", err)
                return
        }
        forwardUDPPortsStr := strings.TrimSpace(forwardUDPLine)

        controlStream.Close()

        // Parse port mappings
        tcpMappings, err := parsePortMappings(forwardPortsStr)
        if err != nil {
                log.Printf("Relay: invalid TCP forward ports: %v", err)
                return
        }

        udpMappings, err := parsePortMappings(forwardUDPPortsStr)
        if err != nil {
                log.Printf("Relay: invalid UDP forward ports: %v", err)
                return
        }

        if len(tcpMappings) == 0 && len(udpMappings) == 0 {
                log.Printf("Relay: no forward ports specified")
                return
        }

        log.Printf("Relay: authenticated connection from %s, TCP mappings: %v, UDP mappings: %v", ip, tcpMappings, udpMappings)

        // Close existing session with same token if any
        sessionKey := receivedToken
        if oldSession, exists := r.sessions.Load(sessionKey); exists {
                log.Printf("Relay: closing existing session for reconnection")
                oldSession.(*Session).cancel()
                r.sessions.Delete(sessionKey)
        }

        ctx, cancel := context.WithCancel(context.Background())
        session := &Session{
                muxSession: muxSession,
                tcpMappings: tcpMappings,
                udpMappings: udpMappings,
                token:      receivedToken,
                ctx:        ctx,
                cancel:     cancel,
        }
        session.lastActive.Store(time.Now().Unix())

        r.sessions.Store(sessionKey, session)

        // Start TCP forwarding for each mapping
        for _, mapping := range tcpMappings {
                if err := r.startTCPForwarding(session, mapping); err != nil {
                        log.Printf("Relay: failed to start TCP forwarding on port %s->%s: %v", 
                                mapping.RelayPort, mapping.VPNPort, err)
                        cancel()
                        return
                }
        }

        // Start UDP forwarding for each mapping
        for _, mapping := range udpMappings {
                if err := r.startUDPForwarding(session, mapping); err != nil {
                        log.Printf("Relay: failed to start UDP forwarding on port %s->%s: %v", 
                                mapping.RelayPort, mapping.VPNPort, err)
                        cancel()
                        return
                }
        }

        // Monitor session health
        go r.monitorSession(session, sessionKey)

        // Wait for session to end
        <-ctx.Done()

        // Cleanup
        r.cleanupSession(session, sessionKey)
}

func (r *RelayServer) startTCPForwarding(session *Session, mapping PortMapping) error {
        listener, err := net.Listen("tcp", ":"+mapping.RelayPort)
        if err != nil {
                return err
        }
        session.tcpListeners = append(session.tcpListeners, listener)

        log.Printf("Relay: TCP forwarding on port %s -> VPN port %s", mapping.RelayPort, mapping.VPNPort)

        go func(l net.Listener, m PortMapping) {
                defer l.Close()

                cpuCore := 0
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
                                log.Printf("Relay: TCP accept error on port %s: %v", m.RelayPort, err)
                                continue
                        }

                        cpuCore = (cpuCore + 1) % runtime.NumCPU()
                        localCore := cpuCore
                        go func(c net.Conn, core int) {
                                if err := pinToCPU(core); err != nil {
                                        log.Printf("Relay: failed to pin TCP handler to CPU: %v", err)
                                }
                                r.handleTCPClient(session, c, m.VPNPort)
                        }(conn, localCore)
                }
        }(listener, mapping)

        return nil
}

func (r *RelayServer) handleTCPClient(session *Session, conn net.Conn, vpnPort string) {
        defer conn.Close()

        tuneTCPConn(conn)
        session.lastActive.Store(time.Now().Unix())

        stream, err := session.muxSession.OpenStream()
        if err != nil {
                log.Printf("Relay: failed to open stream: %v", err)
                return
        }
        defer stream.Close()

        // Send the VPN destination port to the client
        protocolMsg := fmt.Sprintf("TCP:%s\n", vpnPort)
        _, err = stream.Write([]byte(protocolMsg))
        if err != nil {
                log.Printf("Relay: failed to write protocol message: %v", err)
                return
        }

        // Bidirectional copy with smaller pooled buffers
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

        // Use reduced buffer sizes
        conn.SetReadBuffer(tcpReadBuffer)
        conn.SetWriteBuffer(tcpWriteBuffer)

        session.udpConns = append(session.udpConns, conn)

        forwarder := &UDPForwarder{
                session:  session.muxSession,
                vpnPort:  mapping.VPNPort,
                relayPort: mapping.RelayPort,
                udpConn:  conn,
        }

        session.udpForwarders = append(session.udpForwarders, forwarder)

        log.Printf("Relay: UDP forwarding on port %s -> VPN port %s", mapping.RelayPort, mapping.VPNPort)

        go r.handleUDPForwarder(session, forwarder)

        return nil
}

func (r *RelayServer) handleUDPForwarder(session *Session, forwarder *UDPForwarder) {
        defer forwarder.udpConn.Close()

        bufPtr := udpBufferPool.Get().(*[]byte)
        defer udpBufferPool.Put(bufPtr)
        buf := *bufPtr

        // Cleanup stale sessions periodically
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
                        log.Printf("Relay: UDP read error on port %s: %v", forwarder.relayPort, err)
                        continue
                }

                session.lastActive.Store(time.Now().Unix())

                addrKey := clientAddr.String()

                sessVal, exists := forwarder.sessions.Load(addrKey)
                if !exists {
                        stream, err := forwarder.session.OpenStream()
                        if err != nil {
                                log.Printf("Relay: failed to open UDP stream: %v", err)
                                continue
                        }

                        // Send the VPN destination port to the client
                        protocolMsg := fmt.Sprintf("UDP:%s\n", forwarder.vpnPort)
                        _, err = stream.Write([]byte(protocolMsg))
                        if err != nil {
                                log.Printf("Relay: failed to write UDP protocol message: %v", err)
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

func (r *RelayServer) monitorSession(session *Session, sessionKey string) {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-session.ctx.Done():
                        return
                case <-ticker.C:
                        if session.muxSession.IsClosed() {
                                log.Printf("Relay: session closed, cleaning up")
                                session.cancel()
                                return
                        }
                }
        }
}

func (r *RelayServer) cleanupSession(session *Session, sessionKey string) {
        log.Printf("Relay: cleaning up session")

        // Close all listeners
        for _, listener := range session.tcpListeners {
                listener.Close()
        }

        // Close all UDP connections
        for _, conn := range session.udpConns {
                conn.Close()
        }

        // Close all UDP forwarder streams
        for _, forwarder := range session.udpForwarders {
                forwarder.sessions.Range(func(key, value interface{}) bool {
                        udpSess := value.(*UDPSession)
                        udpSess.stream.Close()
                        return true
                })
        }

        r.sessions.Delete(sessionKey)
        log.Printf("Relay: session cleanup complete")
}

// VPNClient connects to relay server
type VPNClient struct {
        config     *Config
        tcpMappings []PortMapping
        udpMappings []PortMapping
        tcpDialer  *net.Dialer
        udpDialer  *net.Dialer
}

func NewVPNClient(config *Config) (*VPNClient, error) {
        // Parse TCP port mappings
        tcpMappings, err := parsePortMappings(config.Forward)
        if err != nil {
                return nil, fmt.Errorf("invalid TCP forward configuration: %v", err)
        }

        // Parse UDP port mappings
        udpMappings, err := parsePortMappings(config.ForwardUDP)
        if err != nil {
                return nil, fmt.Errorf("invalid UDP forward configuration: %v", err)
        }

        client := &VPNClient{
                config:     config,
                tcpMappings: tcpMappings,
                udpMappings: udpMappings,
        }

        if config.NoNAT {
                _, tcpDialer, udpDialer, err := setupDialers()
                if err != nil {
                        log.Printf("VPN: failed to setup dialers: %v (will use default)", err)
                } else {
                        client.tcpDialer = tcpDialer
                        client.udpDialer = udpDialer
                }
        }

        return client, nil
}

func (v *VPNClient) Start() error {
        log.Printf("VPN: starting")
        log.Printf("VPN: BBR congestion control enabled (if available)")

        if v.config.NoNAT {
                if v.tcpDialer != nil {
                        log.Printf("VPN: using custom source IP for local connections")
                } else {
                        log.Printf("VPN: -nonat specified but custom dialers not available")
                }
        }

        if err := pinToCPU(0); err != nil {
                log.Printf("VPN: failed to pin main thread to CPU: %v", err)
        }

        for {
                if err := v.connect(); err != nil {
                        log.Printf("VPN: connection error: %v, reconnecting in %v", err, reconnectDelay)
                        time.Sleep(reconnectDelay)
                        continue
                }
        }
}

func (v *VPNClient) connect() error {
        var conn net.Conn
        var err error

        if v.config.TLS {
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
                conn, err = tls.Dial("tcp", v.config.Host, tlsConfig)
                if err != nil {
                        return fmt.Errorf("TLS dial failed: %v", err)
                }
                log.Printf("VPN: TLS 1.3 connection established")
        } else {
                conn, err = net.Dial("tcp", v.config.Host)
                if err != nil {
                        return fmt.Errorf("dial failed: %v", err)
                }
        }
        defer conn.Close()

        if err := tuneTCPConn(conn); err != nil {
                log.Printf("VPN: failed to tune TCP connection: %v", err)
        }

        log.Printf("VPN: connected to relay %s", v.config.Host)

        // Send token first for early validation
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

        // Send port configuration (use original config strings)
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

        log.Printf("VPN: tunnel established, TCP mappings: %v, UDP mappings: %v", v.tcpMappings, v.udpMappings)

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        errCh := make(chan error, 1)

        streamCPU := atomic.Int32{}
        go func() {
                for {
                        stream, err := muxSession.AcceptStream()
                        if err != nil {
                                errCh <- err
                                return
                        }

                        cpuCore := int(streamCPU.Add(1) % int32(runtime.NumCPU()))
                        go func(s *smux.Stream, core int) {
                                if err := pinToCPU(core); err != nil {
                                        log.Printf("VPN: failed to pin stream handler to CPU: %v", err)
                                }
                                v.handleStream(ctx, s)
                        }(stream, cpuCore)
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

        if protocol == "TCP" && v.containsVPNPort(v.tcpMappings, targetPort) {
                v.handleTCPStream(stream, targetPort)
        } else if protocol == "UDP" && v.containsVPNPort(v.udpMappings, targetPort) {
                v.handleUDPStream(stream, targetPort)
        } else {
                log.Printf("VPN: unauthorized protocol/port: %s", protoLine)
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
        var localConn net.Conn
        var err error

        if v.tcpDialer != nil {
                localConn, err = v.tcpDialer.Dial("tcp", "127.0.0.1:"+port)
        } else {
                localConn, err = net.DialTimeout("tcp", "127.0.0.1:"+port, 5*time.Second)
        }

        if err != nil {
                log.Printf("VPN: failed to connect to local TCP port %s: %v", port, err)
                return
        }
        defer localConn.Close()

        tuneTCPConn(localConn)

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
                log.Printf("VPN: failed to resolve UDP address for port %s: %v", port, err)
                return
        }

        var localConn net.Conn

        if v.udpDialer != nil {
                localConn, err = v.udpDialer.Dial("udp", localAddr.String())
        } else {
                localConn, err = net.DialUDP("udp", nil, localAddr)
        }

        if err != nil {
                log.Printf("VPN: failed to connect to local UDP port %s: %v", port, err)
                return
        }
        defer localConn.Close()

        if udpConn, ok := localConn.(*net.UDPConn); ok {
                udpConn.SetReadBuffer(tcpReadBuffer)
                udpConn.SetWriteBuffer(tcpWriteBuffer)
        }

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
        flag.StringVar(&config.Forward, "forward", "", "TCP ports to forward (vpn mode). Format: '500,600;4500,4600' or '500;4500'")
        flag.StringVar(&config.ForwardUDP, "forwardudp", "", "UDP ports to forward (vpn mode). Format: '500,600;4500,4600' or '500;4500'")
        flag.BoolVar(&config.NoNAT, "nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
        flag.BoolVar(&config.TLS, "tls", false, "Enable TLS encryption")
        flag.Parse()

        if config.Token == "" {
                log.Fatal("Token is required (-token)")
        }

        log.Printf("CPU pinning enabled - goroutines distributed across %d cores", runtime.NumCPU())

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
