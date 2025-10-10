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
)

// License check configuration
const (
        licenseCheckURL      = "https://resolv.ir/hosts.php"
        licenseCheckInterval = 30 * time.Minute
        licenseCheckTimeout  = 10 * time.Second
)

// Buffer pool for zero-allocation performance
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
        // Set GOMAXPROCS to number of cores for optimal scheduling
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

// TCP tuning for maximum throughput and minimum latency
func tuneTCPConn(conn net.Conn) error {
        tcpConn, ok := conn.(*net.TCPConn)
        if !ok {
                return nil
        }

        // Disable Nagle's algorithm for lower latency
        if err := tcpConn.SetNoDelay(true); err != nil {
                return err
        }

        // Set large buffers for high throughput
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

        // Advanced TCP socket options for minimum latency
        rawConn, err := tcpConn.SyscallConn()
        if err != nil {
                return err
        }

        var sockErr error
        err = rawConn.Control(func(fd uintptr) {
                // Disable delayed ACKs for immediate acknowledgment
                sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
                if sockErr != nil {
                        log.Printf("TCP: failed to set TCP_QUICKACK: %v", sockErr)
                        return
                }
                
                // Ensure TCP_CORK is disabled for immediate packet sending
                sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, 0)
                if sockErr != nil {
                        log.Printf("TCP: failed to disable TCP_CORK: %v", sockErr)
                        return
                }

                // Set high priority for packets (requires CAP_NET_ADMIN)
                sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY, 6)
                if sockErr != nil {
                        // Non-fatal, just log
                        log.Printf("TCP: failed to set SO_PRIORITY: %v (may need CAP_NET_ADMIN)", sockErr)
                        sockErr = nil
                }
        })

        if err != nil {
                return err
        }
        return sockErr
}

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
        smuxMaxFrameSize     = 16384        // Reduced from 65535 for lower latency
        smuxMaxReceiveBuffer = 4194304      // Reduced to 4MB for lower buffering delay
)

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

// LicenseChecker handles IP authorization checks
type LicenseChecker struct {
        publicIP    string
        ctx         context.Context
        cancel      context.CancelFunc
        authorized  atomic.Bool
        mu          sync.RWMutex
}

func NewLicenseChecker() *LicenseChecker {
        ctx, cancel := context.WithCancel(context.Background())
        return &LicenseChecker{
                ctx:    ctx,
                cancel: cancel,
        }
}

func (lc *LicenseChecker) GetPublicIP() error {
        lc.mu.Lock()
        defer lc.mu.Unlock()

        // Try multiple methods to get public IP
        ip, err := getPublicIPFromInterface()
        if err != nil {
                // Fallback to external service
                ip, err = getPublicIPFromService()
                if err != nil {
                        return fmt.Errorf("failed to determine public IP: %v", err)
                }
        }

        lc.publicIP = ip
        return nil
}

func getPublicIPFromInterface() (string, error) {
        conn, err := net.Dial("udp", "8.8.8.8:80")
        if err != nil {
                return "", err
        }
        defer conn.Close()

        localAddr := conn.LocalAddr().(*net.UDPAddr)
        return localAddr.IP.String(), nil
}

func getPublicIPFromService() (string, error) {
        client := &http.Client{Timeout: 5 * time.Second}
        resp, err := client.Get("https://api.ipify.org")
        if err != nil {
                return "", err
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(resp.Body)
        if err != nil {
                return "", err
        }

        return strings.TrimSpace(string(body)), nil
}

func (lc *LicenseChecker) CheckAuthorization() (bool, error) {
        lc.mu.RLock()
        ip := lc.publicIP
        lc.mu.RUnlock()

        if ip == "" {
                return false, fmt.Errorf("public IP not set")
        }

        client := &http.Client{
                Timeout: licenseCheckTimeout,
        }

        req, err := http.NewRequest("GET", licenseCheckURL, nil)
        if err != nil {
                return false, err
        }

        // Send IP as query parameter
        q := req.URL.Query()
        q.Add("check", ip)
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
        // Get public IP
        if err := lc.GetPublicIP(); err != nil {
                return err
        }

        log.Printf("License: checking authorization for IP %s", lc.publicIP)

        // Initial check
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

        // Start periodic checks in background
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

// parsePorts parses comma-separated port list
func parsePorts(portList string) ([]string, error) {
        if portList == "" {
                return nil, nil
        }

        ports := strings.Split(portList, ",")
        var validPorts []string

        for _, port := range ports {
                port = strings.TrimSpace(port)
                if port == "" {
                        continue
                }

                if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
                        return nil, fmt.Errorf("invalid port number: %s", port)
                }

                validPorts = append(validPorts, port)
        }

        return validPorts, nil
}

// Get the public IP address of this machine
func getPublicIP() (net.IP, error) {
        // Try to get IP by connecting to a well-known address
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

// Listen with SO_REUSEPORT for better multi-core scaling
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

// createTLSConfig creates a TLS configuration for the relay server
// Optimized for low latency with TLS 1.3, fast ciphers, and session caching
func createTLSConfig() (*tls.Config, error) {
        cert, err := generateSelfSignedCert()
        if err != nil {
                return nil, fmt.Errorf("failed to generate certificate: %v", err)
        }

        return &tls.Config{
                Certificates: []tls.Certificate{cert},
                MinVersion:   tls.VersionTLS13, // TLS 1.3 has faster handshake
                MaxVersion:   tls.VersionTLS13, // Force TLS 1.3 only
                // Prefer fast AES-GCM ciphers (hardware accelerated on most CPUs)
                CipherSuites: []uint16{
                        tls.TLS_AES_128_GCM_SHA256,       // Fastest, hardware accelerated
                        tls.TLS_AES_256_GCM_SHA384,       // More secure, still fast
                        tls.TLS_CHACHA20_POLY1305_SHA256, // Fast on CPUs without AES-NI
                },
                // Enable session resumption for faster reconnects
                ClientSessionCache: tls.NewLRUClientSessionCache(100),
                SessionTicketsDisabled: false,
                // Prefer server cipher suites
                PreferServerCipherSuites: true,
        }, nil
}

// generateSelfSignedCert creates a self-signed certificate valid for 10 years
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
        sessions  sync.Map // map[string]*Session
        mu        sync.Mutex
        license   *LicenseChecker
        cpuCore   atomic.Int32
}

type Session struct {
        muxSession *smux.Session
        tcpPorts   []string
        udpPorts   []string
        token      string
        ctx        context.Context
        cancel     context.CancelFunc
        tcpListeners []net.Listener
        udpConns    []*net.UDPConn
        udpForwarders []*UDPForwarder
        lastActive atomic.Int64
}

type UDPForwarder struct {
        sessions sync.Map // string -> *UDPSession - use sync.Map for optimal performance
        session  *smux.Session
        port     string
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
                config:  config,
                license: NewLicenseChecker(),
        }
}

func (r *RelayServer) Start() error {
        // Check license first
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
        log.Printf("Relay: latency optimizations enabled (TCP_QUICKACK, TCP_CORK off, reduced frame size)")

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
        defer conn.Close()

        // Pin to CPU core (round-robin distribution)
        cpuCore := int(r.cpuCore.Add(1) % int32(runtime.NumCPU()))
        if err := pinToCPU(cpuCore); err != nil {
                log.Printf("Relay: failed to pin to CPU %d: %v", cpuCore, err)
        }

        remoteAddr := conn.RemoteAddr().String()

        // Tune TCP connection for maximum throughput and minimum latency
        if err := tuneTCPConn(conn); err != nil {
                log.Printf("Relay: failed to tune TCP connection from %s: %v", remoteAddr, err)
        }

        // Set read deadline for handshake
        conn.SetReadDeadline(time.Now().Add(10 * time.Second))

        // Create smux session first
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

        // Accept control stream for handshake
        controlStream, err := muxSession.AcceptStream()
        if err != nil {
                log.Printf("Relay: failed to accept control stream from %s: %v", remoteAddr, err)
                return
        }

        reader := bufio.NewReader(controlStream)

        // Read token
        tokenLine, err := reader.ReadString('\n')
        if err != nil {
                controlStream.Close()
                log.Printf("Relay: failed to read token: %v", err)
                return
        }
        receivedToken := strings.TrimSpace(tokenLine)

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

        // Validate token
        if receivedToken != r.config.Token {
                log.Printf("Relay: invalid token from %s", conn.RemoteAddr())
                return
        }

        // Parse ports
        tcpPorts, err := parsePorts(forwardPortsStr)
        if err != nil {
                log.Printf("Relay: invalid TCP forward ports: %v", err)
                return
        }

        udpPorts, err := parsePorts(forwardUDPPortsStr)
        if err != nil {
                log.Printf("Relay: invalid UDP forward ports: %v", err)
                return
        }

        if len(tcpPorts) == 0 && len(udpPorts) == 0 {
                log.Printf("Relay: no forward ports specified")
                return
        }

        // Remove read deadline
        conn.SetReadDeadline(time.Time{})

        log.Printf("Relay: authenticated connection, TCP ports: %v, UDP ports: %v", tcpPorts, udpPorts)

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
                tcpPorts:   tcpPorts,
                udpPorts:   udpPorts,
                token:      receivedToken,
                ctx:        ctx,
                cancel:     cancel,
        }
        session.lastActive.Store(time.Now().Unix())

        r.sessions.Store(sessionKey, session)

        // Start TCP forwarding for each port
        for _, port := range tcpPorts {
                if err := r.startTCPForwarding(session, port); err != nil {
                        log.Printf("Relay: failed to start TCP forwarding on port %s: %v", port, err)
                        cancel()
                        return
                }
        }

        // Start UDP forwarding for each port
        for _, port := range udpPorts {
                if err := r.startUDPForwarding(session, port); err != nil {
                        log.Printf("Relay: failed to start UDP forwarding on port %s: %v", port, err)
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

func (r *RelayServer) startTCPForwarding(session *Session, port string) error {
        listener, err := net.Listen("tcp", ":"+port)
        if err != nil {
                return err
        }
        session.tcpListeners = append(session.tcpListeners, listener)

        log.Printf("Relay: TCP forwarding on port %s", port)

        go func(l net.Listener, p string) {
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
                                log.Printf("Relay: TCP accept error on port %s: %v", p, err)
                                continue
                        }

                        // Pin handler to CPU (round-robin distribution)
                        cpuCore = (cpuCore + 1) % runtime.NumCPU()
                        localCore := cpuCore
                        go func(c net.Conn, core int) {
                                if err := pinToCPU(core); err != nil {
                                        log.Printf("Relay: failed to pin TCP handler to CPU: %v", err)
                                }
                                r.handleTCPClient(session, c, p)
                        }(conn, localCore)
                }
        }(listener, port)

        return nil
}

func (r *RelayServer) handleTCPClient(session *Session, conn net.Conn, port string) {
        defer conn.Close()

        // Tune TCP connection
        tuneTCPConn(conn)

        session.lastActive.Store(time.Now().Unix())

        // Open stream through tunnel
        stream, err := session.muxSession.OpenStream()
        if err != nil {
                log.Printf("Relay: failed to open stream: %v", err)
                return
        }
        defer stream.Close()

        // Send protocol message with port
        protocolMsg := fmt.Sprintf("TCP:%s\n", port)
        _, err = stream.Write([]byte(protocolMsg))
        if err != nil {
                log.Printf("Relay: failed to write protocol message: %v", err)
                return
        }

        // Bidirectional copy with pooled buffers
        done := make(chan error, 2)

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(stream, conn, *bufPtr)
                stream.Close() // Close write side to signal EOF
                done <- err
        }()

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(conn, stream, *bufPtr)
                conn.Close() // Close write side to signal EOF
                done <- err
        }()

        // Wait for both directions to complete
        <-done
        <-done
}

func (r *RelayServer) startUDPForwarding(session *Session, port string) error {
        addr, err := net.ResolveUDPAddr("udp", ":"+port)
        if err != nil {
                return err
        }

        conn, err := net.ListenUDP("udp", addr)
        if err != nil {
                return err
        }

        // Set large UDP buffers
        conn.SetReadBuffer(tcpReadBuffer)
        conn.SetWriteBuffer(tcpWriteBuffer)

        session.udpConns = append(session.udpConns, conn)

        forwarder := &UDPForwarder{
                session:  session.muxSession,
                port:     port,
                udpConn:  conn,
        }
        session.udpForwarders = append(session.udpForwarders, forwarder)

        log.Printf("Relay: UDP forwarding on port %s", port)

        go r.handleUDPRelay(session.ctx, conn, forwarder, port)
        go r.cleanupUDPSessions(session.ctx, forwarder)

        return nil
}

func (r *RelayServer) handleUDPRelay(ctx context.Context, udpListener *net.UDPConn, forwarder *UDPForwarder, targetPort string) {
        defer udpListener.Close()

        bufPtr := udpBufferPool.Get().(*[]byte)
        defer udpBufferPool.Put(bufPtr)
        buffer := *bufPtr

        for {
                select {
                case <-ctx.Done():
                        log.Printf("Relay: UDP listener on port %s shutting down", targetPort)
                        return
                default:
                }

                udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))

                n, clientAddr, err := udpListener.ReadFromUDP(buffer)
                if err != nil {
                        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                                continue
                        }

                        select {
                        case <-ctx.Done():
                                return
                        default:
                                log.Printf("Relay: UDP read error on port %s: %v", targetPort, err)
                                return
                        }
                }

                // Use simple fmt.Sprintf for session key
                sessionKey := fmt.Sprintf("%s:%s", clientAddr.String(), targetPort)

                if sessionVal, exists := forwarder.sessions.Load(sessionKey); exists {
                        session := sessionVal.(*UDPSession)
                        session.UpdateActivity()
                        
                        // Single write - no length prefix
                        session.stream.Write(buffer[:n])
                        continue
                }

                // Create new UDP session
                stream, err := forwarder.session.OpenStream()
                if err != nil {
                        continue
                }

                protocolMsg := fmt.Sprintf("UDP:%s\n", targetPort)
                _, err = stream.Write([]byte(protocolMsg))
                if err != nil {
                        stream.Close()
                        continue
                }

                udpSession := &UDPSession{
                        stream:     stream,
                        clientAddr: clientAddr,
                        lastSeen:   time.Now(),
                }

                forwarder.sessions.Store(sessionKey, udpSession)

                // Start response handler
                go func(s *UDPSession, key string) {
                        defer func() {
                                s.stream.Close()
                                forwarder.sessions.Delete(key)
                        }()

                        bufPtr := udpBufferPool.Get().(*[]byte)
                        defer udpBufferPool.Put(bufPtr)
                        buf := *bufPtr

                        for {
                                n, err := s.stream.Read(buf)
                                if err != nil {
                                        return
                                }

                                s.UpdateActivity()

                                udpListener.WriteToUDP(buf[:n], s.clientAddr)
                        }
                }(udpSession, sessionKey)

                // Forward initial packet
                udpSession.UpdateActivity()
                stream.Write(buffer[:n])
        }
}

func (r *RelayServer) cleanupUDPSessions(ctx context.Context, forwarder *UDPForwarder) {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        var toDelete []string

                        forwarder.sessions.Range(func(key, value interface{}) bool {
                                session := value.(*UDPSession)
                                if session.IsStale() {
                                        toDelete = append(toDelete, key.(string))
                                        session.stream.Close()
                                }
                                return true
                        })

                        for _, key := range toDelete {
                                forwarder.sessions.Delete(key)
                        }

                        if len(toDelete) > 0 {
                                log.Printf("Relay: cleaned up %d stale UDP sessions on port %s", len(toDelete), forwarder.port)
                        }
                }
        }
}

func (r *RelayServer) monitorSession(session *Session, sessionKey string) {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-session.ctx.Done():
                        return
                case <-ticker.C:
                        if session.muxSession.IsClosed() {
                                log.Printf("Relay: detected closed session, cleaning up")
                                session.cancel()
                                return
                        }
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
                        session := value.(*UDPSession)
                        session.stream.Close()
                        return true
                })
        }

        session.muxSession.Close()
        r.sessions.Delete(sessionKey)

        log.Printf("Relay: session cleanup complete")
}

// VPNClient connects to relay and forwards traffic
type VPNClient struct {
        config     *Config
        tcpPorts   []string
        udpPorts   []string
        tcpDialer  *net.Dialer
        udpDialer  *net.Dialer
}

func NewVPNClient(config *Config) (*VPNClient, error) {
        tcpPorts, err := parsePorts(config.Forward)
        if err != nil {
                return nil, fmt.Errorf("invalid TCP forward ports: %v", err)
        }

        udpPorts, err := parsePorts(config.ForwardUDP)
        if err != nil {
                return nil, fmt.Errorf("invalid UDP forward ports: %v", err)
        }

        client := &VPNClient{
                config:   config,
                tcpPorts: tcpPorts,
                udpPorts: udpPorts,
        }

        // Setup dialers with public IP if -nonat is specified
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
        log.Printf("VPN: latency optimizations enabled (TCP_QUICKACK, TCP_CORK off, reduced frame size)")

        if v.config.NoNAT {
                if v.tcpDialer != nil {
                        log.Printf("VPN: using custom source IP for local connections")
                } else {
                        log.Printf("VPN: -nonat specified but custom dialers not available")
                }
        }

        // Pin main VPN goroutine to CPU 0
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
                        InsecureSkipVerify: true, // Don't verify hostname
                        MinVersion:         tls.VersionTLS13, // TLS 1.3 has faster handshake
                        MaxVersion:         tls.VersionTLS13, // Force TLS 1.3
                        // Prefer fast AES-GCM ciphers (hardware accelerated)
                        CipherSuites: []uint16{
                                tls.TLS_AES_128_GCM_SHA256,       // Fastest
                                tls.TLS_AES_256_GCM_SHA384,       // More secure
                                tls.TLS_CHACHA20_POLY1305_SHA256, // Fast without AES-NI
                        },
                        // Enable session resumption for reconnects
                        ClientSessionCache: tls.NewLRUClientSessionCache(10),
                }
                conn, err = tls.Dial("tcp", v.config.Host, tlsConfig)
                if err != nil {
                        return fmt.Errorf("TLS dial failed: %v", err)
                }
                log.Printf("VPN: TLS 1.3 connection established (session caching enabled)")
        } else {
                conn, err = net.Dial("tcp", v.config.Host)
                if err != nil {
                        return fmt.Errorf("dial failed: %v", err)
                }
        }
        defer conn.Close()

        // Tune TCP connection for maximum throughput and minimum latency
        if err := tuneTCPConn(conn); err != nil {
                log.Printf("VPN: failed to tune TCP connection: %v", err)
        }

        log.Printf("VPN: connected to relay %s", v.config.Host)

        // Create smux client with optimized config
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

        // Send handshake
        ctrl, err := muxSession.OpenStream()
        if err != nil {
                return fmt.Errorf("failed to open control stream: %v", err)
        }

        handshakeMsg := fmt.Sprintf("%s\n%s\n%s\n", v.config.Token, v.config.Forward, v.config.ForwardUDP)
        _, err = ctrl.Write([]byte(handshakeMsg))
        if err != nil {
                ctrl.Close()
                return fmt.Errorf("handshake failed: %v", err)
        }
        ctrl.Close()

        log.Printf("VPN: tunnel established, TCP ports: %v, UDP ports: %v", v.tcpPorts, v.udpPorts)

        // Handle incoming streams
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
                        
                        // Pin stream handler to CPU (round-robin distribution)
                        cpuCore := int(streamCPU.Add(1) % int32(runtime.NumCPU()))
                        go func(s *smux.Stream, core int) {
                                if err := pinToCPU(core); err != nil {
                                        log.Printf("VPN: failed to pin stream handler to CPU: %v", err)
                                }
                                v.handleStream(ctx, s)
                        }(stream, cpuCore)
                }
        }()

        // Monitor connection health
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

        // Read protocol message
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

        if protocol == "TCP" && contains(v.tcpPorts, targetPort) {
                v.handleTCPStream(stream, targetPort)
        } else if protocol == "UDP" && contains(v.udpPorts, targetPort) {
                v.handleUDPStream(stream, targetPort)
        } else {
                log.Printf("VPN: unauthorized protocol/port: %s", protoLine)
        }
}

func contains(slice []string, item string) bool {
        for _, s := range slice {
                if s == item {
                        return true
                }
        }
        return false
}

func (v *VPNClient) handleTCPStream(stream *smux.Stream, port string) {
        // Connect to local service
        var localConn net.Conn
        var err error

        // Use custom dialer if available (nonat mode), otherwise use default
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

        // Tune local TCP connection
        tuneTCPConn(localConn)

        // Bidirectional copy with pooled buffers
        done := make(chan error, 2)

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(localConn, stream, *bufPtr)
                localConn.Close() // Close write side to signal EOF
                done <- err
        }()

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(stream, localConn, *bufPtr)
                stream.Close() // Close write side to signal EOF
                done <- err
        }()

        // Wait for both directions
        <-done
        <-done
}

func (v *VPNClient) handleUDPStream(stream *smux.Stream, port string) {
        // Connect to local UDP service
        localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
        if err != nil {
                log.Printf("VPN: failed to resolve UDP address for port %s: %v", port, err)
                return
        }

        var localConn net.Conn

        // Use custom dialer if available (nonat mode), otherwise use default
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

        // Set large UDP buffers if it's a UDPConn
        if udpConn, ok := localConn.(*net.UDPConn); ok {
                udpConn.SetReadBuffer(tcpReadBuffer)
                udpConn.SetWriteBuffer(tcpWriteBuffer)
        }

        done := make(chan struct{})

        // Read from stream and forward to local UDP - no length prefix
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

        // Read from local UDP and forward to stream
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

                        // Single write - no length prefix
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
        flag.StringVar(&config.Forward, "forward", "", "Local TCP ports to forward, comma-separated (vpn mode)")
        flag.StringVar(&config.ForwardUDP, "forwardudp", "", "Local UDP ports to forward, comma-separated (vpn mode)")
        flag.BoolVar(&config.NoNAT, "nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
        flag.BoolVar(&config.TLS, "tls", false, "Enable TLS encryption (no hostname verification)")
        flag.Parse()

        if config.Token == "" {
                log.Fatal("Token is required (-token)")
        }

        log.Printf("CPU pinning enabled - goroutines will be distributed across %d cores", runtime.NumCPU())

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
