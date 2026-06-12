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

const (
        // idle timeout for TCP forwarded connections (both directions)
        idleTimeout = 2 * time.Minute

        // udp mapping stale timeout
        udpMapStaleTimeout = 2 * time.Minute

        // how often to cleanup stale UDP mappings
        udpCleanupInterval = 30 * time.Second

        // registration wait timeout (how long relay waits for VPN to send registration stream)
        registrationWaitTimeout = 15 * time.Second

        // grace windows to tolerate short reconnects
        tcpReattachGrace = 30 * time.Second // how long to keep pending TCP connections / keep listener usable
        udpMetaGrace     = 30 * time.Second // how long to keep UDP meta after session closes
)

func main() {
        mode := flag.String("mode", "", "Mode: relay or vpn")
        host := flag.String("host", "", "Relay server host (vpn mode)")
        port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
        forward := flag.String("forward", "", "Forwarding spec for TCP: relaySrc,localTarget (e.g. 8443,8444)")
        forwardudp := flag.String("forwardudp", "", "Forwarding spec for UDP: relaySrc,localTarget (e.g. 8443,8444)")
        token := flag.String("token", "", "Shared token (required) used to authenticate VPN and Relay over the TLS control channel")
        flag.Parse()

        if *token == "" {
                log.Fatalf("a -token is required for both relay and vpn modes")
        }

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
                runRelay(ctx, wg, *port, *token)
        case "vpn":
                if *host == "" || *port == "" || *forward == "" {
                        log.Fatal("vpn mode requires -host, -port, and -forward")
                }
                runVPN(ctx, wg, *host, *port, *forward, *forwardudp, *token)
        default:
                log.Fatal("Invalid mode, use relay or vpn")
        }

        // wait for background goroutines to finish
        wg.Wait()
        log.Println("shutdown complete")
}

// parseForwardSpec accepts "src,target", "src:target", "port" and returns (src,target) as strings.
// If only one port is provided, it is used for both src and target.
func parseForwardSpec(spec string) (string, string, error) {
        spec = strings.TrimSpace(spec)
        if spec == "" {
                return "", "", fmt.Errorf("empty spec")
        }
        var parts []string
        if strings.Contains(spec, ",") {
                parts = strings.SplitN(spec, ",", 2)
        } else if strings.Contains(spec, ":") {
                parts = strings.SplitN(spec, ":", 2)
        } else {
                // single port, use for both
                parts = []string{spec, spec}
        }
        if len(parts) != 2 {
                return "", "", fmt.Errorf("invalid spec %q", spec)
        }
        src := strings.TrimSpace(parts[0])
        dst := strings.TrimSpace(parts[1])
        // basic validation: numeric ports
        if _, err := strconv.Atoi(src); err != nil {
                return "", "", fmt.Errorf("invalid source port %q", src)
        }
        if _, err := strconv.Atoi(dst); err != nil {
                return "", "", fmt.Errorf("invalid target port %q", dst)
        }
        return src, dst, nil
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

func runRelay(ctx context.Context, wg *sync.WaitGroup, port string, expectedToken string) {
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
                                        handleControlChannel(ctx, c, expectedToken)
                                }(conn)
                        }
                }
        }()

        acceptWg.Wait()
        log.Println("relay: stopped accepting control connections")
}

type udpSessionMeta struct {
        expectedCSID   uint32
        expectedAuth   []byte // 16 bytes
        vpnPeer        net.Addr
        vpnPeerLock    sync.RWMutex
        clientLock     sync.RWMutex
        addrToCSID     map[string]uint32
        csidToAddr     map[uint32]net.Addr
        addrLastActive map[string]time.Time
        csidLastActive map[uint32]time.Time
        nextRandomMtx  sync.Mutex

        // pending buffering fields (not used in this flow)
        pending   map[string][][]byte
        pendingTs map[string]time.Time
}

// --- udpManager: keep UDP socket bound for process lifetime and swap session meta on reconnect ---

// udpManager owns a PacketConn for a given relay UDP port and can host at most one
// active udpSessionMeta at a time. The socket is kept bound for the lifetime of the
// process (or until the manager is explicitly stopped), which avoids bind/rebind races
// when control sessions disconnect/reconnect frequently.
type udpManager struct {
        port string
        pc   net.PacketConn

        mu   sync.RWMutex
        meta *udpSessionMeta

        ctx    context.Context
        cancel context.CancelFunc
        done   chan struct{}
}

var (
        udpManagers   = make(map[string]*udpManager)
        udpManagersMu sync.Mutex
)

// getOrCreateUDPManager returns a manager for the given port, creating it if necessary.
func getOrCreateUDPManager(parentCtx context.Context, port string) (*udpManager, error) {
        udpManagersMu.Lock()
        m, ok := udpManagers[port]
        if ok {
                udpManagersMu.Unlock()
                return m, nil
        }

        pc, err := net.ListenPacket("udp", ":"+port)
        if err != nil {
                udpManagersMu.Unlock()
                return nil, err
        }

        ctx, cancel := context.WithCancel(parentCtx)
        m = &udpManager{
                port:   port,
                pc:     pc,
                ctx:    ctx,
                cancel: cancel,
                done:   make(chan struct{}),
        }
        udpManagers[port] = m
        udpManagersMu.Unlock()

        // start main loop (based on relayUDPHandler)
        go m.run()
        log.Printf("relay: udpManager created and listening on :%s", port)
        return m, nil
}

// setMeta installs (or clears) the current udpSessionMeta for the manager.
func (m *udpManager) setMeta(meta *udpSessionMeta) {
        m.mu.Lock()
        m.meta = meta
        m.mu.Unlock()
}

// getMeta returns the current meta (can be nil).
func (m *udpManager) getMeta() *udpSessionMeta {
        m.mu.RLock()
        defer m.mu.RUnlock()
        return m.meta
}

// stop closes the manager and its socket.
func (m *udpManager) stop() {
        m.cancel()
        <-m.done
        m.pc.Close()
}

// run is adapted from relayUDPHandler but reads the active meta dynamically.
func (m *udpManager) run() {
        defer close(m.done)
        buf := make([]byte, 65535)
        cleanupTicker := time.NewTicker(udpCleanupInterval)
        defer cleanupTicker.Stop()

        for {
                select {
                case <-m.ctx.Done():
                        log.Printf("relay: udpManager on :%s shutting down", m.port)
                        return
                case <-cleanupTicker.C:
                        meta := m.getMeta()
                        if meta == nil {
                                continue
                        }
                        now := time.Now()
                        meta.clientLock.Lock()
                        for addrStr, last := range meta.addrLastActive {
                                if now.Sub(last) > udpMapStaleTimeout {
                                        csid := meta.addrToCSID[addrStr]
                                        delete(meta.addrToCSID, addrStr)
                                        delete(meta.addrLastActive, addrStr)
                                        delete(meta.csidToAddr, csid)
                                        delete(meta.csidLastActive, csid)
                                        log.Printf("relay: removed stale UDP client mapping %s (clientSessionID %d)", addrStr, csid)
                                }
                        }
                        for addrStr, ts := range meta.pendingTs {
                                if now.Sub(ts) > udpMapStaleTimeout {
                                        cnt := len(meta.pending[addrStr])
                                        delete(meta.pending, addrStr)
                                        delete(meta.pendingTs, addrStr)
                                        if cnt > 0 {
                                                log.Printf("relay: dropped %d pending buffered UDP packets for %s due to TTL", cnt, addrStr)
                                        }
                                }
                        }
                        meta.clientLock.Unlock()
                default:
                }

                _ = m.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
                n, addr, err := m.pc.ReadFrom(buf)
                if err != nil {
                        if ne, ok := err.(net.Error); ok && ne.Timeout() {
                                continue
                        }
                        log.Printf("relay: UDP listener on :%s closed or error: %v", m.port, err)
                        return
                }
                if n == 0 {
                        continue
                }
                data := buf[:n]

                meta := m.getMeta()

                // If no meta is configured, ignore registration/data until someone registers via control channel.
                if meta == nil {
                        // However we still want to accept registration from a reconnecting VPN
                        // only if a control session immediately installs a meta; dropping is safe.
                        log.Printf("relay: udpManager :%s received UDP but no session registered yet; dropping", m.port)
                        continue
                }

                // Process register: 0x01 | csid(4) | auth(16)
                if len(data) >= 1 && data[0] == 0x01 {
                        if len(data) < 1+4+16 {
                                log.Printf("relay: malformed register packet from %s on :%s", addr.String(), m.port)
                                continue
                        }
                        csid := binary.BigEndian.Uint32(data[1 : 1+4])
                        auth := data[1+4 : 1+4+16]
                        if csid != meta.expectedCSID || !equalBytes(auth, meta.expectedAuth) {
                                log.Printf("relay: UDP register from %s failed auth (csid mismatch or auth mismatch)", addr.String())
                                continue
                        }

                        meta.vpnPeerLock.RLock()
                        prevPeer := meta.vpnPeer
                        meta.vpnPeerLock.RUnlock()

                        needLog := prevPeer == nil || prevPeer.String() != addr.String()

                        meta.vpnPeerLock.Lock()
                        meta.vpnPeer = addr
                        meta.vpnPeerLock.Unlock()

                        ack := make([]byte, 1+4)
                        ack[0] = 0x03
                        binary.BigEndian.PutUint32(ack[1:5], csid)
                        _, _ = m.pc.WriteTo(ack, addr)

                        if needLog {
                                log.Printf("relay: registered VPN UDP peer %s for csid=%d on :%s", addr.String(), csid, m.port)
                        }
                        continue
                }

                // Packet from vpn peer: 0x02 | csid(4) | clientSessionID(4) | payload...
                meta.vpnPeerLock.RLock()
                vpnPeer := meta.vpnPeer
                meta.vpnPeerLock.RUnlock()

                if vpnPeer != nil && addr.String() == vpnPeer.String() {
                        if data[0] != 0x02 {
                                log.Printf("relay: unknown packet type %02x from vpn peer on :%s", data[0], m.port)
                                continue
                        }
                        if len(data) < 1+4+4 {
                                log.Printf("relay: malformed data packet from vpn peer (too short) on :%s", m.port)
                                continue
                        }
                        csid := binary.BigEndian.Uint32(data[1:5])
                        if csid != meta.expectedCSID {
                                log.Printf("relay: csid mismatch in packet from vpn peer: got %d expected %d", csid, meta.expectedCSID)
                                continue
                        }
                        clientSessionID := binary.BigEndian.Uint32(data[5:9])
                        payload := data[9:n]

                        meta.clientLock.RLock()
                        dst, ok := meta.csidToAddr[clientSessionID]
                        meta.clientLock.RUnlock()
                        if !ok {
                                log.Printf("relay: unknown clientSessionID %d from vpn peer, dropping", clientSessionID)
                                continue
                        }
                        _, err = m.pc.WriteTo(payload, dst)
                        if err != nil {
                                log.Printf("relay: failed to forward UDP payload to external client %s: %v", dst.String(), err)
                        } else {
                                meta.clientLock.Lock()
                                meta.csidLastActive[clientSessionID] = time.Now()
                                meta.addrLastActive[dst.String()] = time.Now()
                                meta.clientLock.Unlock()
                        }
                        continue
                }

                // Packet from external client: map addr -> clientSessionID (create if new) and forward to vpn peer
                meta.clientLock.Lock()
                clientAddrStr := addr.String()
                csid := meta.expectedCSID
                clientSID, exists := meta.addrToCSID[clientAddrStr]
                if !exists {
                        clientSID = randomNonZeroUint32(func(v uint32) bool {
                                _, exists2 := meta.csidToAddr[v]
                                return exists2
                        })
                        meta.addrToCSID[clientAddrStr] = clientSID
                        meta.csidToAddr[clientSID] = addr
                        meta.addrLastActive[clientAddrStr] = time.Now()
                        meta.csidLastActive[clientSID] = time.Now()
                        log.Printf("relay: new external UDP client %s assigned clientSessionID %d on :%s", clientAddrStr, clientSID, m.port)
                } else {
                        meta.addrLastActive[clientAddrStr] = time.Now()
                        meta.csidLastActive[clientSID] = time.Now()
                }
                meta.clientLock.Unlock()

                meta.vpnPeerLock.RLock()
                currVpn := meta.vpnPeer
                meta.vpnPeerLock.RUnlock()
                if currVpn == nil {
                        log.Printf("relay: received UDP from %s but no VPN peer registered yet for this UDP forward port; dropping", addr.String())
                        continue
                }

                out := make([]byte, 1+4+4+len(data))
                out[0] = 0x02
                binary.BigEndian.PutUint32(out[1:5], csid)
                binary.BigEndian.PutUint32(out[5:9], clientSID)
                copy(out[9:], data)
                _, err = m.pc.WriteTo(out, currVpn)
                if err != nil {
                        log.Printf("relay: failed to forward UDP frame to vpn peer %s: %v", currVpn.String(), err)
                }
        }
}

// relayUDPHandler handles plain UDP forwarding for one control session
func relayUDPHandler(ctx context.Context, pc net.PacketConn, meta *udpSessionMeta) {
        // kept for compatibility, though the udpManager.run implementation is preferred
        buf := make([]byte, 65535)

        // cleanup ticker to remove stale addr/csid entries
        cleanupTicker := time.NewTicker(udpCleanupInterval)
        defer cleanupTicker.Stop()

        for {
                select {
                case <-ctx.Done():
                        log.Println("relay: udp handler context cancelled")
                        return
                case <-cleanupTicker.C:
                        if meta == nil {
                                continue
                        }
                        now := time.Now()
                        // cleanup stale addrToCSID
                        meta.clientLock.Lock()
                        for addrStr, last := range meta.addrLastActive {
                                if now.Sub(last) > udpMapStaleTimeout {
                                        csid := meta.addrToCSID[addrStr]
                                        delete(meta.addrToCSID, addrStr)
                                        delete(meta.addrLastActive, addrStr)
                                        delete(meta.csidToAddr, csid)
                                        delete(meta.csidLastActive, csid)
                                        log.Printf("relay: removed stale UDP client mapping %s (clientSessionID %d)", addrStr, csid)
                                }
                        }
                        // pending cleanup if used (not used in this flow)
                        for addrStr, ts := range meta.pendingTs {
                                if now.Sub(ts) > udpMapStaleTimeout {
                                        cnt := len(meta.pending[addrStr])
                                        delete(meta.pending, addrStr)
                                        delete(meta.pendingTs, addrStr)
                                        if cnt > 0 {
                                                log.Printf("relay: dropped %d pending buffered UDP packets for %s due to TTL", cnt, addrStr)
                                        }
                                }
                        }
                        meta.clientLock.Unlock()
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
                        if meta == nil || csid != meta.expectedCSID || !equalBytes(auth, meta.expectedAuth) {
                                log.Printf("relay: UDP register from %s failed auth (csid mismatch or auth mismatch)", addr.String())
                                continue
                        }

                        // only log when vpnPeer changes (suppress repeated logs)
                        meta.vpnPeerLock.RLock()
                        prevPeer := meta.vpnPeer
                        meta.vpnPeerLock.RUnlock()

                        needLog := prevPeer == nil || prevPeer.String() != addr.String()

                        // set vpn peer for this UDP forward socket
                        meta.vpnPeerLock.Lock()
                        meta.vpnPeer = addr
                        meta.vpnPeerLock.Unlock()

                        // send ack: 0x03 | csid(4)
                        ack := make([]byte, 1+4)
                        ack[0] = 0x03
                        binary.BigEndian.PutUint32(ack[1:5], csid)
                        _, _ = pc.WriteTo(ack, addr) // best-effort

                        if needLog {
                                log.Printf("relay: registered VPN UDP peer %s for csid=%d", addr.String(), csid)
                        }
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
                        if meta == nil || csid != meta.expectedCSID {
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
                        } else {
                                // update last active for csid/client addr
                                meta.clientLock.Lock()
                                meta.csidLastActive[clientSessionID] = time.Now()
                                meta.addrLastActive[dst.String()] = time.Now()
                                meta.clientLock.Unlock()
                        }
                        continue
                }

                // Packet from external client: we need to map addr -> clientSessionID (create if new) and forward to vpn peer
                if meta == nil {
                        // no UDP meta configured, drop
                        continue
                }
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
                        meta.addrLastActive[clientAddrStr] = time.Now()
                        meta.csidLastActive[clientSID] = time.Now()
                        log.Printf("relay: new external UDP client %s assigned clientSessionID %d", clientAddrStr, clientSID)
                } else {
                        meta.addrLastActive[clientAddrStr] = time.Now()
                        meta.csidLastActive[clientSID] = time.Now()
                }
                meta.clientLock.Unlock()

                // Ensure vpnPeer present
                meta.vpnPeerLock.RLock()
                currVpn := meta.vpnPeer
                meta.vpnPeerLock.RUnlock()
                if currVpn == nil {
                        // VPN hasn't registered its UDP peer via UDP 0x01 yet; we drop client packets until the VPN's UDP registration arrives.
                        // However because the relay replied "READY" on the registration stream, the VPN should now send the UDP 0x01 immediately,
                        // so this should be transient.
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

func runVPN(ctx context.Context, wg *sync.WaitGroup, relayHost, relayPort, forwardSpec, forwardUDPSpec string, token string) {
        // forwardSpec is the user-provided spec like "8443,8444"
        relayTcpSrc, localTcpTarget, err := parseForwardSpec(forwardSpec)
        if err != nil {
                log.Fatalf("vpn: invalid -forward spec %q: %v", forwardSpec, err)
        }
        var relayUdpSrc, localUdpTarget string
        if forwardUDPSpec != "" {
                relayUdpSrc, localUdpTarget, err = parseForwardSpec(forwardUDPSpec)
                if err != nil {
                        log.Fatalf("vpn: invalid -forwardudp spec %q: %v", forwardUDPSpec, err)
                }
        }

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
                        // retry quickly every 1s (no backoff)
                        time.Sleep(1 * time.Second)
                        continue
                }
                log.Printf("vpn: TLS Control Channel established to relay %s:%s", relayHost, relayPort)

                // Send token and forwarding specs over the TLS control channel (pre-smux)
                // token line first (mandatory)
                _, err = fmt.Fprintf(controlChannelConn, "%s\n", token)
                if err != nil {
                        log.Printf("vpn: failed to send token to relay: %v", err)
                        controlChannelConn.Close()
                        time.Sleep(1 * time.Second)
                        continue
                }

                // send TCP forward source and UDP forward source and csid/auth later as before
                if relayUdpSrc != "" {
                        // we'll prepare csid/auth later; send the src ports first (tcpLine, udpLine)
                        _, err = fmt.Fprintf(controlChannelConn, "%s\n%s\n", relayTcpSrc, relayUdpSrc)
                        if err != nil {
                                log.Printf("vpn: failed to send forward ports to relay via Control Channel: %v", err)
                                controlChannelConn.Close()
                                time.Sleep(1 * time.Second)
                                continue
                        }
                } else {
                        _, err = fmt.Fprintf(controlChannelConn, "%s\n\n", relayTcpSrc)
                        if err != nil {
                                log.Printf("vpn: failed to send forward ports to relay via Control Channel: %v", err)
                                controlChannelConn.Close()
                                time.Sleep(1 * time.Second)
                                continue
                        }
                }

                // If UDP forward requested, create csid and auth token and send them now
                var csid uint32
                var authToken []byte
                if relayUdpSrc != "" {
                        csid = randomUint32()
                        authToken = make([]byte, 16)
                        _, err := rand.Read(authToken)
                        if err != nil {
                                log.Printf("vpn: failed to generate udp auth token: %v", err)
                                controlChannelConn.Close()
                                time.Sleep(1 * time.Second)
                                continue
                        }
                        _, err = fmt.Fprintf(controlChannelConn, "%d\n%s\n", csid, hex.EncodeToString(authToken))
                        if err != nil {
                                log.Printf("vpn: failed to send csid/auth to relay via Control Channel: %v", err)
                                controlChannelConn.Close()
                                time.Sleep(1 * time.Second)
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
                        time.Sleep(1 * time.Second)
                        continue
                }

                // Registration over smux control channel so relay will open forwarded listeners.
                // Wait for the relay to reply "READY\n" before sending the UDP 0x01 registration, to avoid the bind race.
                regStream, err := session.OpenStream()
                if err != nil {
                        log.Printf("vpn: failed to open registration stream: %v", err)
                        session.Close()
                        controlChannelConn.Close()
                        time.Sleep(1 * time.Second)
                        continue
                }
                _, err = fmt.Fprintf(regStream, "REGISTER\n")
                if err != nil {
                        log.Printf("vpn: failed to write REGISTER over smux: %v", err)
                        regStream.Close()
                        session.Close()
                        controlChannelConn.Close()
                        time.Sleep(1 * time.Second)
                        continue
                }
                // wait for READY or ERROR (with a timeout)
                _ = regStream.SetReadDeadline(time.Now().Add(10 * time.Second))
                respBuf := bufio.NewReader(regStream)
                reply, rerr := respBuf.ReadString('\n')
                if rerr != nil {
                        log.Printf("vpn: registration handshake failed (no reply) over smux: %v", rerr)
                        regStream.Close()
                        session.Close()
                        controlChannelConn.Close()
                        time.Sleep(1 * time.Second)
                        continue
                }
                reply = strings.TrimSpace(reply)
                if reply != "READY" {
                        log.Printf("vpn: registration rejected by relay: %q", reply)
                        regStream.Close()
                        session.Close()
                        controlChannelConn.Close()
                        time.Sleep(1 * time.Second)
                        continue
                }
                regStream.Close()
                log.Printf("vpn: registration handshake completed, relay replied READY")

                // If UDP forward requested, establish plain UDP connection to relay's UDP port and register
                var udpConn net.PacketConn
                var udpRemote net.Addr
                var udpDone chan struct{}
                if relayUdpSrc != "" {
                        raddr := net.JoinHostPort(relayHost, relayUdpSrc)
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

                                        ackChan := make(chan struct{}, 1)
                                        udpDone = make(chan struct{})

                                        // Start vpnUDPHandler (it will signal ackChan upon receiving ACK 0x03).
                                        wg.Add(1)
                                        go func() {
                                                defer wg.Done()
                                                vpnUDPHandler(ctx, udpConn, udpRemote, csid, localUdpTarget, ackChan)
                                                close(udpDone)
                                        }()

                                        // Send initial registration and start a retry loop that stops when ackChan receives ACK.
                                        _, err = udpConn.WriteTo(reg, udpRemote)
                                        if err != nil {
                                                log.Printf("vpn: failed to send UDP registration to relay %s: %v", raddr, err)
                                                udpConn.Close()
                                                udpConn = nil
                                        } else {
                                                log.Printf("vpn: sent UDP registration to relay %s from local %s (csid=%d)", raddr, udpConn.LocalAddr().String(), csid)
                                                // retry loop until ack or timeout
                                                go func() {
                                                        retryTicker := time.NewTicker(1 * time.Second)
                                                        defer retryTicker.Stop()
                                                        timeout := time.After(10 * time.Second)
                                                        for {
                                                                select {
                                                                case <-ctx.Done():
                                                                        return
                                                                case <-ackChan:
                                                                        // got ack from relay, stop retrying
                                                                        return
                                                                case <-timeout:
                                                                        // stop retrying after timeout
                                                                        return
                                                                case <-retryTicker.C:
                                                                        _, _ = udpConn.WriteTo(reg, udpRemote)
                                                                }
                                                        }
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
                        streamErr <- handleVPNStreamsWithCtx(ctx, session, localTcpTarget)
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
                        if udpDone != nil {
                                <-udpDone
                        }
                }
                // if ctx isn't done, attempt reconnect quickly (1s)
                select {
                case <-ctx.Done():
                        log.Println("vpn: exiting run loop due to context cancellation")
                        return
                default:
                        log.Println("vpn: Control Channel closed, reconnecting in 1 second...")
                        time.Sleep(1 * time.Second)
                }
        }
}

func handleVPNStreamsWithCtx(ctx context.Context, session *smux.Session, localForwardPort string) error {
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
                go handleVPNStreamWithIdle(stream, localForwardPort)
        }
}

func handleVPNStreamWithIdle(stream *smux.Stream, forwardPort string) {
        defer stream.Close()

        localConn, err := net.Dial("tcp", "127.0.0.1:"+forwardPort)
        if err != nil {
                log.Printf("vpn: failed to connect to localhost:%s: %v", forwardPort, err)
                return
        }
        defer localConn.Close()

        log.Printf("vpn: forwarding Control Channel stream to localhost:%s", forwardPort)
        // use idle-aware forward to avoid leaking
        forwardConnectionWithIdleTimeout(stream, localConn, idleTimeout)
}

// vpnUDPHandler demultiplexes incoming frames from relay and forwards to local UDP service,
// and sends responses back to relay. It keeps per-client local UDP sockets keyed by clientSessionID.
// ackChan is used to notify the registration sender when it receives the relay ACK (0x03).
func vpnUDPHandler(ctx context.Context, pc net.PacketConn, relayAddr net.Addr, csid uint32, localForwardPort string, ackChan chan struct{}) {
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
                        mu.Lock()
                        for k, e := range localMap {
                                if time.Since(e.lastActive) > 2*time.Minute {
                                        close(e.stopCh)
                                        e.conn.Close()
                                        delete(localMap, k)
                                        log.Printf("vpn: removed stale local UDP mapping for clientSID %d", k)
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
                // accept only packets from the relay address (remote)
                if addr.String() != relayAddr.String() {
                        // ignore unexpected senders
                        log.Printf("vpn: ignoring UDP packet from unexpected addr %s (expecting %s)", addr.String(), relayAddr.String())
                        continue
                }
                if n == 0 {
                        continue
                }
                data := buf[:n]

                // ACK from relay: 0x03 | csid(4)
                if data[0] == 0x03 {
                        if len(data) >= 1+4 {
                                rCsid := binary.BigEndian.Uint32(data[1:5])
                                if rCsid == csid {
                                        // notify registration sender (non-blocking)
                                        select {
                                        case ackChan <- struct{}{}:
                                        default:
                                        }
                                }
                        }
                        continue
                }

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

// ---- persistent tcpManager to survive control disconnects ----

// tcpManager keeps a single long-lived TCP listener per port and holds pending accepted
// connections while no smux session is attached. When a session is attached it opens
// streams for pending connections and forwards them.
type tcpManager struct {
        port     string
        ln       net.Listener
        ctx      context.Context
        cancel   context.CancelFunc
        done     chan struct{}

        mu            sync.RWMutex
        session       *smux.Session
        pending       []*pendingConn
        pendingMu     sync.Mutex
        reattachGrace time.Duration
}

type pendingConn struct {
        conn     net.Conn
        accepted time.Time
        attached bool
}

var (
        tcpManagers   = make(map[string]*tcpManager)
        tcpManagersMu sync.Mutex
)

func getOrCreateTCPManager(parentCtx context.Context, port string) (*tcpManager, error) {
        tcpManagersMu.Lock()
        if m, ok := tcpManagers[port]; ok {
                tcpManagersMu.Unlock()
                return m, nil
        }

        ln, err := net.Listen("tcp", ":"+port)
        if err != nil {
                tcpManagersMu.Unlock()
                return nil, err
        }

        ctx, cancel := context.WithCancel(parentCtx)
        m := &tcpManager{
                port:          port,
                ln:            ln,
                ctx:           ctx,
                cancel:        cancel,
                done:          make(chan struct{}),
                pending:       make([]*pendingConn, 0),
                reattachGrace: tcpReattachGrace,
        }
        tcpManagers[port] = m
        tcpManagersMu.Unlock()

        go m.run()
        log.Printf("relay: tcpManager created and listening on :%s", port)
        return m, nil
}

func (m *tcpManager) run() {
        defer close(m.done)

        for {
                if tl, ok := m.ln.(*net.TCPListener); ok {
                        _ = tl.SetDeadline(time.Now().Add(1 * time.Second))
                }
                conn, err := m.ln.Accept()
                if err != nil {
                        if ne, ok := err.(net.Error); ok && ne.Timeout() {
                                select {
                                case <-m.ctx.Done():
                                        return
                                default:
                                        continue
                                }
                        }
                        log.Printf("relay: tcpManager accept error on :%s: %v", m.port, err)
                        return
                }

                log.Printf("relay: tcpManager accepted forwarded connection from %s on :%s", conn.RemoteAddr(), m.port)

                // try to attach immediately if a session is present; otherwise store in pending list
                if m.tryAttach(conn) {
                        continue
                }

                pc := &pendingConn{conn: conn, accepted: time.Now(), attached: false}
                m.pendingMu.Lock()
                m.pending = append(m.pending, pc)
                m.pendingMu.Unlock()
        }
}

func (m *tcpManager) tryAttach(conn net.Conn) bool {
        m.mu.RLock()
        sess := m.session
        m.mu.RUnlock()
        if sess == nil {
                return false
        }

        // open stream
        stream, err := sess.OpenStream()
        if err != nil {
                // session present but failed to open stream — treat as no-session for now
                log.Printf("relay: tcpManager failed to open stream for conn %s: %v", conn.RemoteAddr(), err)
                return false
        }

        log.Printf("relay: tcpManager created stream for conn %s", conn.RemoteAddr())
        // forward
        go forwardConnectionWithIdleTimeout(conn, stream, idleTimeout)
        return true
}

// attachPending attempts to drain pending list and attach streams for each pending connection.
func (m *tcpManager) attachPending() {
        m.mu.RLock()
        sess := m.session
        m.mu.RUnlock()
        if sess == nil {
                return
        }

        m.pendingMu.Lock()
        pending := m.pending
        m.pending = nil // we'll reappend those we couldn't attach
        m.pendingMu.Unlock()

        for _, pc := range pending {
                if pc.attached {
                        continue
                }
                stream, err := sess.OpenStream()
                if err != nil {
                        log.Printf("relay: tcpManager failed to open stream for pending conn %s: %v", pc.conn.RemoteAddr(), err)
                        m.pendingMu.Lock()
                        m.pending = append(m.pending, pc)
                        m.pendingMu.Unlock()
                        continue
                }
                pc.attached = true
                log.Printf("relay: tcpManager attached pending conn %s to new stream", pc.conn.RemoteAddr())
                go forwardConnectionWithIdleTimeout(pc.conn, stream, idleTimeout)
        }
}

// setSession sets the active smux session used to attach streams and will try to attach pending conns.
func (m *tcpManager) setSession(s *smux.Session) {
        m.mu.Lock()
        m.session = s
        m.mu.Unlock()
        if s != nil {
                go m.attachPending()
        }
}

// clearSessionIfMatches clears the current session pointer only if it matches 's'.
// it will wait for a grace window before clearing to allow short reconnects to reuse the manager.
func (m *tcpManager) clearSessionIfMatches(s *smux.Session) {
        go func() {
                timer := time.NewTimer(m.reattachGrace)
                defer timer.Stop()
                <-timer.C
                m.mu.Lock()
                if m.session == s {
                        m.session = nil
                        log.Printf("relay: tcpManager cleared session on :%s after grace window", m.port)
                } else {
                        log.Printf("relay: tcpManager session on :%s changed during grace window; not clearing", m.port)
                }
                m.mu.Unlock()
        }()
}

func (m *tcpManager) stop() {
        m.cancel()
        <-m.done
        m.ln.Close()
}

// ---- common helpers ----

// forwardConnectionWithIdleTimeout mirrors data between two net.Conn objects but ensures that
// if no activity is observed for idle duration both sides are closed to avoid resource leaks.
func forwardConnectionWithIdleTimeout(a, b net.Conn, idle time.Duration) {
        defer a.Close()
        defer b.Close()

        done := make(chan struct{}, 2)
        var lastMu sync.Mutex
        last := time.Now()
        updateActivity := func() {
                lastMu.Lock()
                last = time.Now()
                lastMu.Unlock()
        }

        // copy a -> b
        go func() {
                buf := make([]byte, 32*1024)
                for {
                        _ = a.SetReadDeadline(time.Now().Add(10 * time.Second))
                        n, rerr := a.Read(buf)
                        if n > 0 {
                                updateActivity()
                                written := 0
                                for written < n {
                                        _ = b.SetWriteDeadline(time.Now().Add(10 * time.Second))
                                        wn, werr := b.Write(buf[written:n])
                                        if wn > 0 {
                                                updateActivity()
                                                written += wn
                                        }
                                        if werr != nil {
                                                rerr = werr
                                                break
                                        }
                                }
                        }
                        if rerr != nil {
                                if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
                                        lastMu.Lock()
                                        elapsed := time.Since(last)
                                        lastMu.Unlock()
                                        if elapsed > idle {
                                                break
                                        }
                                        continue
                                }
                                break
                        }
                }
                done <- struct{}{}
        }()

        // copy b -> a
        go func() {
                buf := make([]byte, 32*1024)
                for {
                        _ = b.SetReadDeadline(time.Now().Add(10 * time.Second))
                        n, rerr := b.Read(buf)
                        if n > 0 {
                                updateActivity()
                                written := 0
                                for written < n {
                                        _ = a.SetWriteDeadline(time.Now().Add(10 * time.Second))
                                        wn, werr := a.Write(buf[written:n])
                                        if wn > 0 {
                                                updateActivity()
                                                written += wn
                                        }
                                        if werr != nil {
                                                rerr = werr
                                                break
                                        }
                                }
                        }
                        if rerr != nil {
                                if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
                                        lastMu.Lock()
                                        elapsed := time.Since(last)
                                        lastMu.Unlock()
                                        if elapsed > idle {
                                                break
                                        }
                                        continue
                                }
                                break
                        }
                }
                done <- struct{}{}
        }()

        <-done
}

// forwardConnection kept for backward compatibility but uses the idle-aware variant
func forwardConnection(forwardedConn, stream net.Conn) {
        forwardConnectionWithIdleTimeout(forwardedConn, stream, idleTimeout)
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

// handleControlChannel now requires the expectedToken to validate the incoming connection
func handleControlChannel(ctx context.Context, controlChannelConn net.Conn, expectedToken string) {
        defer controlChannelConn.Close()

        reader := bufio.NewReader(controlChannelConn)

        // Read token line first (mandatory)
        tokenLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("relay: failed to read token from VPN client via Control Channel: %v", err)
                return
        }
        tokenLine = strings.TrimSpace(tokenLine)
        if tokenLine == "" {
                log.Printf("relay: empty token from %s; rejecting connection", controlChannelConn.RemoteAddr())
                return
        }
        if tokenLine != expectedToken {
                log.Printf("relay: invalid token from %s; rejecting connection", controlChannelConn.RemoteAddr())
                return
        }
        // token matches
        log.Printf("relay: token authentication succeeded for %s", controlChannelConn.RemoteAddr())

        // Read TCP forward spec line (relaySrc,localTarget). Relay only needs the src.
        tcpLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("relay: failed to read forward TCP spec from VPN client via Control Channel: %v", err)
                return
        }
        tcpLine = strings.TrimSpace(tcpLine)
        relayTcpSrc, _, err := parseForwardSpec(tcpLine)
        if err != nil {
                // if parse fails, try to treat the line as single port (backwards compatibility)
                relayTcpSrc = strings.TrimSpace(tcpLine)
        }
        log.Printf("relay: TCP forwarding source port received via Control Channel: %s", relayTcpSrc)

        // Read UDP forward spec line (or empty)
        udpLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("relay: failed to read forward UDP spec from VPN client via Control Channel: %v", err)
                return
        }
        udpLine = strings.TrimSpace(udpLine)
        var relayUdpSrc string
        if udpLine != "" {
                relayUdpSrc, _, err = parseForwardSpec(udpLine)
                if err != nil {
                        relayUdpSrc = strings.TrimSpace(udpLine)
                }
                log.Printf("relay: UDP forwarding source port received via Control Channel: %s", relayUdpSrc)
        } else {
                log.Printf("relay: no UDP forwarding requested for this Control Channel")
        }

        var meta *udpSessionMeta
        if relayUdpSrc != "" {
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
                        expectedCSID:   uint32(csid64),
                        expectedAuth:   authBytes,
                        addrToCSID:     make(map[string]uint32),
                        csidToAddr:     make(map[uint32]net.Addr),
                        addrLastActive: make(map[string]time.Time),
                        csidLastActive: make(map[uint32]time.Time),
                        pending:        make(map[string][][]byte),
                        pendingTs:      make(map[string]time.Time),
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
        // ensure session closed on exit
        defer session.Close()
        log.Printf("relay: smux session established on Control Channel")

        // incomingStreams receives any streams the VPN opens towards the relay
        incomingStreams := make(chan *smux.Stream)
        sessionClosed := make(chan struct{})

        // goroutine that accepts streams and forwards them to incomingStreams
        go func() {
                for {
                        s, err := session.AcceptStream()
                        if err != nil {
                                close(sessionClosed)
                                return
                        }
                        // deliver stream to handler (non-blocking)
                        select {
                        case incomingStreams <- s:
                        default:
                                // no receiver / slow consumer — close unexpected stream to avoid leaks
                                s.Close()
                        }
                }
        }()

        // Wait for explicit registration from the VPN before opening forwarded listeners.
        // Registration is expected as a short smux stream opened by the VPN. The VPN must open a stream and write "REGISTER\n"
        // within registrationWaitTimeout. After relay binds listeners it will reply "READY\n" on that same stream.
        var regStream *smux.Stream
        select {
        case <-sessionClosed:
                log.Println("relay: smux session closed before registration; exiting control handler")
                return
        case s := <-incomingStreams:
                // Read registration line from this stream
                r := bufio.NewReader(s)
                line, _ := r.ReadString('\n') // tolerate error; treat any non-empty as registration
                line = strings.TrimSpace(line)
                if line == "" {
                        s.Close()
                        log.Println("relay: empty registration line; closing control handler")
                        return
                }
                if line != "REGISTER" {
                        // accept "REGISTER" only for now
                        log.Printf("relay: unexpected registration payload %q; closing control handler", line)
                        s.Close()
                        return
                }
                regStream = s
        case <-time.After(registrationWaitTimeout):
                log.Println("relay: registration wait timed out; closing control handler")
                return
        }

        // At this point, we received REGISTER and have the registration stream open (regStream).
        // Open listeners now so forwarded ports become available immediately.
        log.Printf("relay: received registration from VPN over control stream, binding forwarded listeners for TCP:%s UDP:%s", relayTcpSrc, relayUdpSrc)

        // We'll use managers for TCP and UDP to keep sockets bound across short reconnects.
        var udpMgr *udpManager
        if relayUdpSrc != "" {
                m, err := getOrCreateUDPManager(ctx, relayUdpSrc)
                if err != nil {
                        log.Printf("relay: failed to listen on UDP %s: %v", relayUdpSrc, err)
                        udpMgr = nil
                } else {
                        udpMgr = m
                        // install the session meta into the manager so it will accept registrations for this session
                        udpMgr.setMeta(meta)
                        log.Printf("relay: installed UDP session meta into manager for :%s", relayUdpSrc)
                }
        }

        var tcpMgr *tcpManager
        if relayTcpSrc != "" {
                m, err := getOrCreateTCPManager(ctx, relayTcpSrc)
                if err != nil {
                        log.Printf("relay: failed to ensure TCP listener on %s: %v", relayTcpSrc, err)
                        if udpMgr != nil {
                                // schedule clearing the UDP meta after grace (don't clear immediately)
                                go func(mm *udpManager, expected *udpSessionMeta, port string) {
                                        timer := time.NewTimer(udpMetaGrace)
                                        defer timer.Stop()
                                        <-timer.C
                                        // only clear if still the same meta instance
                                        if mm.getMeta() == expected {
                                                mm.setMeta(nil)
                                                log.Printf("relay: cleared UDP session meta for :%s after grace window", port)
                                        } else {
                                                log.Printf("relay: UDP session meta for :%s changed during grace window; not clearing", port)
                                        }
                                }(udpMgr, meta, relayUdpSrc)
                                log.Printf("relay: scheduled UDP meta clearing for :%s", relayUdpSrc)
                        }
                        regStream.Write([]byte("ERROR\n"))
                        regStream.Close()
                        return
                }
                tcpMgr = m
                // install this smux session into tcp manager so it can attach pending connections
                tcpMgr.setSession(session)
                log.Printf("relay: tcpManager installed session for :%s", relayTcpSrc)
        }

        // Now that listeners are considered bound, reply READY on the registration stream so VPN knows it's safe to send UDP reg
        _, _ = regStream.Write([]byte("READY\n"))
        regStream.Close()

        // wait for sessionClosed or ctx.Done; when sessionClosed happens, we let managers handle graceful clearing
        select {
        case <-ctx.Done():
                log.Println("relay: ctx cancelled, shutting down forwarded listeners")
        case <-sessionClosed:
                log.Println("relay: smux session closed, tearing down forwarded listeners")
        }

        // Instead of force-closing accepted connections immediately, schedule clearing of the session pointer
        // so short reconnects can reattach. tcpManager will clear the session after its grace window if no new session is set.
        if tcpMgr != nil {
                tcpMgr.clearSessionIfMatches(session)
                log.Printf("relay: scheduled tcpManager session clear for :%s (grace %s)", relayTcpSrc, tcpReattachGrace)
        }

        // For UDP: schedule clearing only if it wasn't reinstalled
        if udpMgr != nil {
                go func(mgr *udpManager, expected *udpSessionMeta, port string) {
                        timer := time.NewTimer(udpMetaGrace)
                        defer timer.Stop()
                        <-timer.C
                        // only clear if still the same meta instance
                        if mgr.getMeta() == expected {
                                mgr.setMeta(nil)
                                log.Printf("relay: cleared UDP session meta for :%s after grace window", port)
                        } else {
                                log.Printf("relay: UDP session meta for :%s changed during grace window; not clearing", port)
                        }
                }(udpMgr, meta, relayUdpSrc)
        }

        log.Println("relay: control channel handler exiting (listeners handed off to managers)")
}
