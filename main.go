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
        "encoding/pem"
        "flag"
        "fmt"
        "io"
        "log"
        "math/big"
        "net"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/xtaci/smux"
        "golang.org/x/time/rate"
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

// TCP tuning for maximum throughput
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

        return nil
}

const (
        // Protocol constants
        protocolVersion = byte(1)

        // Configuration - optimized for maximum throughput
        bufferSize       = 128 * 1024 // 128KB buffers for high throughput
        udpBufferSize    = 65535      // Max size for uint16 length prefix
        idleTimeout      = 5 * time.Minute
        reconnectDelay   = 3 * time.Second
        keepAliveInterval = 30 * time.Second

        // TCP tuning for maximum throughput
        tcpReadBuffer  = 4 * 1024 * 1024  // 4MB
        tcpWriteBuffer = 4 * 1024 * 1024  // 4MB

        // smux configuration for maximum performance
        smuxVersion          = 1
        smuxMaxFrameSize     = 65535        // Max uint16 value
        smuxMaxReceiveBuffer = 16777216     // 16MB receive buffer
)

type Config struct {
        Mode       string
        Host       string
        Port       string
        Token      string
        Forward    string
        ForwardUDP string
        Limit      string // e.g., "16m" for 16 Mbps
        NoNAT      bool
        TLS        bool
        limitBytesPerSec int64
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

// parseBandwidthLimit parses bandwidth limit strings like "16m", "100k", "1g"
func parseBandwidthLimit(limit string) (int64, error) {
        if limit == "" {
                return 0, nil
        }

        limit = strings.ToLower(strings.TrimSpace(limit))
        if limit == "" {
                return 0, nil
        }

        // Extract number and unit
        var value float64
        var unit string

        if n, err := fmt.Sscanf(limit, "%f%s", &value, &unit); n < 1 || err != nil {
                return 0, fmt.Errorf("invalid bandwidth limit format: %s", limit)
        }

        // Convert to bits per second (using 1024 multiplier)
        var bitsPerSec float64
        switch unit {
        case "k", "kbps":
                bitsPerSec = value * 1024
        case "m", "mbps":
                bitsPerSec = value * 1024 * 1024
        case "g", "gbps":
                bitsPerSec = value * 1024 * 1024 * 1024
        case "": // No unit, assume Mbps
                bitsPerSec = value * 1024 * 1024
        default:
                return 0, fmt.Errorf("unknown unit: %s (use k, m, or g)", unit)
        }

        // Convert to bytes per second
        bytesPerSec := int64(bitsPerSec / 8)
        return bytesPerSec, nil
}

// RateLimitedReader wraps an io.Reader with rate limiting
type RateLimitedReader struct {
        reader  io.Reader
        limiter *rate.Limiter
}

func NewRateLimitedReader(r io.Reader, bytesPerSec int64) *RateLimitedReader {
        if bytesPerSec <= 0 {
                return &RateLimitedReader{reader: r, limiter: nil}
        }
        // Large burst size to avoid delays: 2x rate or minimum 1MB
        burst := int(bytesPerSec * 2)
        if burst < 1024*1024 {
                burst = 1024 * 1024
        }
        return &RateLimitedReader{
                reader:  r,
                limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst),
        }
}

func (r *RateLimitedReader) Read(p []byte) (int, error) {
        if r.limiter == nil {
                return r.reader.Read(p)
        }

        n, err := r.reader.Read(p)
        if n > 0 {
                // Wait for tokens
                r.limiter.WaitN(context.Background(), n)
        }
        return n, err
}

// RateLimitedWriter wraps an io.Writer with rate limiting
type RateLimitedWriter struct {
        writer  io.Writer
        limiter *rate.Limiter
}

func NewRateLimitedWriter(w io.Writer, bytesPerSec int64) *RateLimitedWriter {
        if bytesPerSec <= 0 {
                return &RateLimitedWriter{writer: w, limiter: nil}
        }
        // Large burst size to avoid delays: 2x rate or minimum 1MB
        burst := int(bytesPerSec * 2)
        if burst < 1024*1024 {
                burst = 1024 * 1024
        }
        return &RateLimitedWriter{
                writer:  w,
                limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst),
        }
}

func (w *RateLimitedWriter) Write(p []byte) (int, error) {
        if w.limiter == nil {
                return w.writer.Write(p)
        }

        // Wait for tokens before writing
        w.limiter.WaitN(context.Background(), len(p))
        return w.writer.Write(p)
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

// createTLSConfig creates a TLS configuration for the relay server
// Generates a self-signed certificate on-the-fly
func createTLSConfig() (*tls.Config, error) {
        cert, err := generateSelfSignedCert()
        if err != nil {
                return nil, fmt.Errorf("failed to generate certificate: %v", err)
        }

        return &tls.Config{
                Certificates: []tls.Certificate{cert},
                MinVersion:   tls.VersionTLS12,
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
        sessions sync.Map // string -> *UDPSession
        session  *smux.Session
        port     string
        udpConn  *net.UDPConn
}

type UDPSession struct {
        stream     *smux.Stream
        clientAddr *net.UDPAddr
        lastSeen   time.Time
        mu         sync.RWMutex
        limiter    *rate.Limiter
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
        var listener net.Listener
        var err error

        if r.config.TLS {
                tlsConfig, err := createTLSConfig()
                if err != nil {
                        return fmt.Errorf("failed to create TLS config: %v", err)
                }
                listener, err = tls.Listen("tcp", ":"+r.config.Port, tlsConfig)
                if err != nil {
                        return fmt.Errorf("failed to start TLS listener: %v", err)
                }
                log.Printf("Relay: TLS enabled")
        } else {
                listener, err = net.Listen("tcp", ":"+r.config.Port)
                if err != nil {
                        return fmt.Errorf("failed to listen: %v", err)
                }
        }
        defer listener.Close()

        if r.config.limitBytesPerSec > 0 {
                log.Printf("Relay: listening on port %s with %d bytes/sec per-connection limit",
                        r.config.Port, r.config.limitBytesPerSec)
        } else {
                log.Printf("Relay: listening on port %s (no bandwidth limit)", r.config.Port)
        }

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

        // Tune TCP connection for maximum throughput
        if err := tuneTCPConn(conn); err != nil {
                log.Printf("Relay: failed to tune TCP connection: %v", err)
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
                log.Printf("Relay: failed to create smux session: %v", err)
                return
        }
        defer muxSession.Close()

        // Accept control stream for handshake
        controlStream, err := muxSession.AcceptStream()
        if err != nil {
                log.Printf("Relay: failed to accept control stream: %v", err)
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

                        go r.handleTCPClient(session, conn, p)
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

        // Apply rate limiting to each connection
        limitedConn := io.ReadWriter(conn)
        limitedStream := io.ReadWriter(stream)

        if r.config.limitBytesPerSec > 0 {
                // Limit both directions independently
                limitedConnReader := NewRateLimitedReader(conn, r.config.limitBytesPerSec)
                limitedConnWriter := NewRateLimitedWriter(conn, r.config.limitBytesPerSec)
                limitedStreamReader := NewRateLimitedReader(stream, r.config.limitBytesPerSec)
                limitedStreamWriter := NewRateLimitedWriter(stream, r.config.limitBytesPerSec)

                limitedConn = struct {
                        io.Reader
                        io.Writer
                }{limitedConnReader, limitedConnWriter}

                limitedStream = struct {
                        io.Reader
                        io.Writer
                }{limitedStreamReader, limitedStreamWriter}
        }

        // Bidirectional copy with buffer pooling
        done := make(chan error, 2)

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(limitedStream, limitedConn, *bufPtr)
                stream.Close() // Close write side to signal EOF
                done <- err
        }()

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(limitedConn, limitedStream, *bufPtr)
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
                session: session.muxSession,
                port:    port,
                udpConn: conn,
        }
        session.udpForwarders = append(session.udpForwarders, forwarder)

        log.Printf("Relay: UDP forwarding on port %s", port)

        go r.handleUDPRelay(session.ctx, conn, forwarder, port)
        go r.cleanupUDPSessions(session.ctx, forwarder)

        return nil
}

func (r *RelayServer) handleUDPRelay(ctx context.Context, udpListener *net.UDPConn, forwarder *UDPForwarder, targetPort string) {
        defer udpListener.Close()
        
        buffer := udpBufferPool.Get().(*[]byte)
        defer udpBufferPool.Put(buffer)

        for {
                select {
                case <-ctx.Done():
                        log.Printf("Relay: UDP listener on port %s shutting down", targetPort)
                        return
                default:
                }

                udpListener.SetReadDeadline(time.Now().Add(1 * time.Second))
                
                n, clientAddr, err := udpListener.ReadFromUDP(*buffer)
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

                sessionKey := fmt.Sprintf("%s:%s", clientAddr.String(), targetPort)

                if sessionVal, exists := forwarder.sessions.Load(sessionKey); exists {
                        session := sessionVal.(*UDPSession)
                        session.UpdateActivity()
                        
                        // Apply rate limiting
                        if session.limiter != nil {
                                session.limiter.WaitN(context.Background(), n+2)
                        }
                        
                        // Write length prefix
                        lenBuf := make([]byte, 2)
                        binary.BigEndian.PutUint16(lenBuf, uint16(n))
                        session.stream.Write(lenBuf)
                        session.stream.Write((*buffer)[:n])
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

                // Create rate limiter for this UDP session
                var limiter *rate.Limiter
                if r.config.limitBytesPerSec > 0 {
                        burst := int(r.config.limitBytesPerSec * 2)
                        if burst < 1024*1024 {
                                burst = 1024 * 1024
                        }
                        limiter = rate.NewLimiter(rate.Limit(r.config.limitBytesPerSec), burst)
                }

                udpSession := &UDPSession{
                        stream:     stream,
                        clientAddr: clientAddr,
                        lastSeen:   time.Now(),
                        limiter:    limiter,
                }

                forwarder.sessions.Store(sessionKey, udpSession)

                // Start response handler
                go func(s *UDPSession, key string) {
                        defer func() {
                                s.stream.Close()
                                forwarder.sessions.Delete(key)
                        }()

                        lenBuf := make([]byte, 2)
                        for {
                                if _, err := io.ReadFull(s.stream, lenBuf); err != nil {
                                        return
                                }

                                length := binary.BigEndian.Uint16(lenBuf)
                                if length == 0 || length > udpBufferSize {
                                        return
                                }

                                bufPtr := udpBufferPool.Get().(*[]byte)
                                data := (*bufPtr)[:length]

                                if _, err := io.ReadFull(s.stream, data); err != nil {
                                        udpBufferPool.Put(bufPtr)
                                        return
                                }

                                s.UpdateActivity()

                                // Apply rate limiting
                                if s.limiter != nil {
                                        s.limiter.WaitN(context.Background(), len(data))
                                }

                                udpListener.WriteToUDP(data, s.clientAddr)
                                udpBufferPool.Put(bufPtr)
                        }
                }(udpSession, sessionKey)

                // Forward initial packet
                udpSession.UpdateActivity()
                
                if limiter != nil {
                        limiter.WaitN(context.Background(), n+2)
                }
                
                lenBuf := make([]byte, 2)
                binary.BigEndian.PutUint16(lenBuf, uint16(n))
                stream.Write(lenBuf)
                stream.Write((*buffer)[:n])
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
        if v.config.limitBytesPerSec > 0 {
                log.Printf("VPN: starting with %d bytes/sec per-connection limit", v.config.limitBytesPerSec)
        } else {
                log.Printf("VPN: starting (no bandwidth limit)")
        }

        if v.config.NoNAT {
                if v.tcpDialer != nil {
                        log.Printf("VPN: using custom source IP for local connections")
                } else {
                        log.Printf("VPN: -nonat specified but custom dialers not available")
                }
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
                }
                conn, err = tls.Dial("tcp", v.config.Host, tlsConfig)
                if err != nil {
                        return fmt.Errorf("TLS dial failed: %v", err)
                }
                log.Printf("VPN: TLS connection established (no hostname verification)")
        } else {
                conn, err = net.Dial("tcp", v.config.Host)
                if err != nil {
                        return fmt.Errorf("dial failed: %v", err)
                }
        }
        defer conn.Close()

        // Tune TCP connection for maximum throughput
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

        // Apply rate limiting to each connection
        limitedLocalConn := io.ReadWriter(localConn)
        limitedStream := io.ReadWriter(stream)

        if v.config.limitBytesPerSec > 0 {
                // Limit both directions independently
                limitedLocalReader := NewRateLimitedReader(localConn, v.config.limitBytesPerSec)
                limitedLocalWriter := NewRateLimitedWriter(localConn, v.config.limitBytesPerSec)
                limitedStreamReader := NewRateLimitedReader(stream, v.config.limitBytesPerSec)
                limitedStreamWriter := NewRateLimitedWriter(stream, v.config.limitBytesPerSec)

                limitedLocalConn = struct {
                        io.Reader
                        io.Writer
                }{limitedLocalReader, limitedLocalWriter}

                limitedStream = struct {
                        io.Reader
                        io.Writer
                }{limitedStreamReader, limitedStreamWriter}
        }

        // Bidirectional copy with buffer pooling
        done := make(chan error, 2)

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(limitedLocalConn, limitedStream, *bufPtr)
                localConn.Close() // Close write side to signal EOF
                done <- err
        }()

        go func() {
                bufPtr := bufferPool.Get().(*[]byte)
                defer bufferPool.Put(bufPtr)
                _, err := io.CopyBuffer(limitedStream, limitedLocalConn, *bufPtr)
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

        // Create rate limiters for UDP
        var readLimiter, writeLimiter *rate.Limiter
        if v.config.limitBytesPerSec > 0 {
                burst := int(v.config.limitBytesPerSec * 2)
                if burst < 1024*1024 {
                        burst = 1024 * 1024
                }
                readLimiter = rate.NewLimiter(rate.Limit(v.config.limitBytesPerSec), burst)
                writeLimiter = rate.NewLimiter(rate.Limit(v.config.limitBytesPerSec), burst)
        }

        done := make(chan struct{})

        // Read from stream and forward to local UDP
        go func() {
                defer close(done)
                lenBuf := make([]byte, 2)

                for {
                        if _, err := io.ReadFull(stream, lenBuf); err != nil {
                                return
                        }

                        length := binary.BigEndian.Uint16(lenBuf)
                        if length == 0 || length > udpBufferSize {
                                return
                        }

                        // Use buffer pool
                        bufPtr := udpBufferPool.Get().(*[]byte)
                        data := (*bufPtr)[:length]

                        if _, err := io.ReadFull(stream, data); err != nil {
                                udpBufferPool.Put(bufPtr)
                                return
                        }

                        // Apply rate limiting
                        if readLimiter != nil {
                                readLimiter.WaitN(context.Background(), len(data))
                        }

                        localConn.Write(data)
                        udpBufferPool.Put(bufPtr)
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

                        // Apply rate limiting
                        if writeLimiter != nil {
                                writeLimiter.WaitN(context.Background(), n+2)
                        }

                        // Write length prefix
                        lenBuf := make([]byte, 2)
                        binary.BigEndian.PutUint16(lenBuf, uint16(n))
                        if _, err := stream.Write(lenBuf); err != nil {
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
        flag.StringVar(&config.Forward, "forward", "", "Local TCP ports to forward, comma-separated (vpn mode)")
        flag.StringVar(&config.ForwardUDP, "forwardudp", "", "Local UDP ports to forward, comma-separated (vpn mode)")
        flag.StringVar(&config.Limit, "limit", "", "Bandwidth limit per connection (e.g., 16m for 16 Mbps)")
        flag.BoolVar(&config.NoNAT, "nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
        flag.BoolVar(&config.TLS, "tls", false, "Enable TLS encryption (no hostname verification)")
        flag.Parse()

        if config.Token == "" {
                log.Fatal("Token is required (-token)")
        }

        // Parse bandwidth limit
        if config.Limit != "" {
                bytesPerSec, err := parseBandwidthLimit(config.Limit)
                if err != nil {
                        log.Fatalf("Invalid bandwidth limit: %v", err)
                }
                config.limitBytesPerSec = bytesPerSec

                // Convert to human-readable format (using 1024 multiplier)
                mbps := float64(bytesPerSec) * 8 / (1024 * 1024)
                log.Printf("Bandwidth limit: %.2f Mbps (%d bytes/sec) per connection", mbps, bytesPerSec)
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
