package main

import (
        "encoding/binary"
        "flag"
        "fmt"
        "hash/fnv"
        "io"
        "log"
        "net"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"

        "github.com/xtaci/smux"
)

const (
        TCP_FORWARD  = 1
        SO_REUSEPORT = 15 // Linux SO_REUSEPORT
)

type ForwardRule struct {
        srcPort    string
        targetPort string
        proto      int // 1 = TCP, 2 = UDP
}

// RelayUDPSession tracks a public client's UDP session on the relay server
type RelayUDPSession struct {
        clientAddr *net.UDPAddr
        srcConn    *net.UDPConn
        lastActive atomic.Int64
}

// VPNUDPSession tracks a local target connection on the VPN client
type VPNUDPSession struct {
        conn       *net.UDPConn
        lastActive atomic.Int64
        closed     bool
        mu         sync.Mutex
}

type RelayConnection struct {
        host          string
        conn          net.Conn
        session       *smux.Session
        active        atomic.Bool
        connected     atomic.Bool
        lastCheck     time.Time
        mu            sync.Mutex
        udpTunnelConn *net.UDPConn
        udpSessions   map[uint32]*VPNUDPSession
        udpSessionsMu sync.Mutex
}

type RelayManager struct {
        relays        []*RelayConnection
        activeRelay   atomic.Value // *RelayConnection
        token         string
        forwardRules  string
        strategy      string // "multi" or "failover"
        reconnectChan chan string
        mu            sync.RWMutex
}

type ActiveRelaySession struct {
        session   *smux.Session
        listeners []io.Closer
        mu        sync.Mutex
}

var (
        mode       = flag.String("mode", "", "Mode: relay or vpn")
        port       = flag.String("port", "", "Relay server port")
        host       = flag.String("host", "", "Relay server host:port (comma-separated for multiple servers)")
        token      = flag.String("token", "", "Authentication token")
        forward    = flag.String("forward", "", "TCP port forwarding (src,target;src,target)")
        forwardudp = flag.String("forwardudp", "", "UDP port forwarding (src,target;src,target)")
        strategy   = flag.String("strategy", "multi", "Strategy: multi (all relays active) or failover (one active at a time)")

        currentRelaySession   *ActiveRelaySession
        currentRelaySessionMu sync.Mutex

        // RAW UDP Tunnel Globals (Relay Side)
        tokenHash           uint64
        relayUDPTunnelConn  *net.UDPConn
        vpnEndpoint         atomic.Value // holds *net.UDPAddr
        relayUDPSessionsMu  sync.RWMutex
        relayUDPSessions    = make(map[string]uint32) // clientAddr.String() -> ID
        relayUDPSessionsRev = make(map[uint32]*RelayUDPSession)
        relayNextSessionID  uint32 = 1

        // Buffer Pools for Zero Allocation
        tcpPool = sync.Pool{
                New: func() any {
                        b := make([]byte, 32*1024)
                        return &b
                },
        }
        framePool = sync.Pool{
                New: func() any {
                        // 65535 max UDP payload + 14 byte header = 65549 bytes
                        b := make([]byte, 65550)
                        return &b
                },
        }
)

func main() {
        flag.Parse()

        if *token == "" {
                log.Fatal("Token is required")
        }

        // Generate a 64-bit FNV-1a hash of the token for lightweight UDP packet authentication
        h := fnv.New64a()
        h.Write([]byte(*token))
        tokenHash = h.Sum64()

        if *mode == "relay" {
                if *port == "" {
                        log.Fatal("Port is required for relay mode")
                }
                runRelay()
        } else if *mode == "vpn" {
                if *host == "" {
                        log.Fatal("Host is required for vpn mode")
                }
                runVPN()
        } else {
                log.Fatal("Invalid mode. Use 'relay' or 'vpn'")
        }
}

func runRelay() {
        // 1. Setup UDP Tunnel Listener
        portInt, err := strconv.Atoi(*port)
        if err != nil {
                log.Fatalf("Invalid port: %v", err)
        }
        udpAddr := &net.UDPAddr{Port: portInt}
        relayUDPTunnelConn, err = net.ListenUDP("udp", udpAddr)
        if err != nil {
                log.Fatalf("Failed to start UDP tunnel listener: %v", err)
        }
        defer relayUDPTunnelConn.Close()

        log.Printf("Relay UDP tunnel listening on :%s", *port)
        go handleRelayUDPTunnel(relayUDPTunnelConn)

        // Background cleanup for stale relay UDP sessions
        go func() {
                ticker := time.NewTicker(30 * time.Second)
                for range ticker.C {
                        relayUDPSessionsMu.Lock()
                        nowNano := time.Now().UnixNano()
                        for id, sess := range relayUDPSessionsRev {
                                if time.Duration(nowNano-sess.lastActive.Load()) > 2*time.Minute {
                                        delete(relayUDPSessions, sess.clientAddr.String())
                                        delete(relayUDPSessionsRev, id)
                                }
                        }
                        relayUDPSessionsMu.Unlock()
                }
        }()

        // 2. Setup TCP Listener
        listener, err := createReusableListener("tcp", ":"+*port)
        if err != nil {
                log.Fatalf("Failed to start TCP relay server: %v", err)
        }
        defer listener.Close()

        log.Printf("Relay TCP server listening on :%s", *port)

        for {
                conn, err := listener.Accept()
                if err != nil {
                        log.Printf("Accept error: %v", err)
                        continue
                }

                go handleRelayConnection(conn)
        }
}

// handleRelayUDPTunnel processes encapsulated UDP traffic from the VPN client
func handleRelayUDPTunnel(conn *net.UDPConn) {
        buf := make([]byte, 65535) // Zero alloc loop
        for {
                n, addr, err := conn.ReadFromUDP(buf)
                if err != nil {
                        break
                }
                if n < 14 {
                        continue // Packet too small for header
                }

                auth := binary.BigEndian.Uint64(buf[0:8])
                if auth != tokenHash {
                        continue // Invalid auth hash
                }

                sessionID := binary.BigEndian.Uint32(buf[8:12])

                // SessionID 0 is a KeepAlive from the VPN client to update NAT mappings
                if sessionID == 0 {
                        vpnEndpoint.Store(addr)
                        continue
                }

                // Otherwise, it's a data payload destined for a public client
                relayUDPSessionsMu.RLock()
                sess, ok := relayUDPSessionsRev[sessionID]
                relayUDPSessionsMu.RUnlock()

                if ok {
                        sess.lastActive.Store(time.Now().UnixNano())
                        sess.srcConn.WriteToUDP(buf[14:n], sess.clientAddr)
                }
        }
}

func closeCurrentSession() {
        currentRelaySessionMu.Lock()
        defer currentRelaySessionMu.Unlock()

        if currentRelaySession != nil {
                currentRelaySession.mu.Lock()
                log.Printf("Closing previous session to allow immediate reconnection...")

                for _, l := range currentRelaySession.listeners {
                        l.Close()
                }
                currentRelaySession.listeners = nil

                if currentRelaySession.session != nil && !currentRelaySession.session.IsClosed() {
                        currentRelaySession.session.Close()
                }
                currentRelaySession.mu.Unlock()

                currentRelaySession = nil
                log.Printf("Previous session closed, ports freed")
        }
}

func setCurrentSession(session *smux.Session) *ActiveRelaySession {
        currentRelaySessionMu.Lock()
        defer currentRelaySessionMu.Unlock()

        currentRelaySession = &ActiveRelaySession{
                session:   session,
                listeners: make([]io.Closer, 0),
        }
        return currentRelaySession
}

func (ars *ActiveRelaySession) addListener(l io.Closer) {
        ars.mu.Lock()
        defer ars.mu.Unlock()
        ars.listeners = append(ars.listeners, l)
}

func handleRelayConnection(conn net.Conn) {
        defer conn.Close()

        if tcpConn, ok := conn.(*net.TCPConn); ok {
                tcpConn.SetNoDelay(true)
        }

        tokLen := len(*token)
        tokBuf := make([]byte, tokLen)
        if _, err := io.ReadFull(conn, tokBuf); err != nil {
                log.Printf("Token read failed from %s: %v", conn.RemoteAddr(), err)
                return
        }
        if string(tokBuf) != *token {
                log.Printf("Authentication failed from %s", conn.RemoteAddr())
                return
        }

        if _, err := conn.Write([]byte("OK")); err != nil {
                log.Printf("Failed to ack auth to %s: %v", conn.RemoteAddr(), err)
                return
        }
        log.Printf("VPN server authenticated: %s", conn.RemoteAddr())

        lenBuf := make([]byte, 2)
        if _, err := io.ReadFull(conn, lenBuf); err != nil {
                log.Printf("Rule length read failed from %s: %v", conn.RemoteAddr(), err)
                return
        }
        ruleLen := binary.BigEndian.Uint16(lenBuf)
        if ruleLen == 0 {
                log.Printf("Empty rule set from %s, aborting handshake", conn.RemoteAddr())
                return
        }

        ruleBuf := make([]byte, ruleLen)
        if _, err := io.ReadFull(conn, ruleBuf); err != nil {
                log.Printf("Rule body read failed from %s: %v", conn.RemoteAddr(), err)
                return
        }

        parts := strings.Split(string(ruleBuf), "|")
        var forwardRules, forwardudpRules string
        if len(parts) >= 1 {
                forwardRules = parts[0]
        }
        if len(parts) >= 2 {
                forwardudpRules = parts[1]
        }
        log.Printf("Received forward rules - TCP: %s, UDP: %s", forwardRules, forwardudpRules)

        smuxConfig := smux.DefaultConfig()
        smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
        smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
        smuxConfig.KeepAliveInterval = 10 * time.Second
        smuxConfig.KeepAliveTimeout = 30 * time.Second

        session, err := smux.Server(conn, smuxConfig)
        if err != nil {
                log.Printf("Failed to create smux session: %v", err)
                return
        }
        defer session.Close()

        // Only tear down the previous session once the new one is fully
        // established. Closing it earlier (e.g. right after auth) leaves a
        // window where a handshake failure below results in zero active
        // TCP listeners and no smux session, with nothing logged.
        closeCurrentSession()

        activeSession := setCurrentSession(session)

        tcpRules := parseForwardRules(forwardRules, TCP_FORWARD)
        udpRules := parseForwardRules(forwardudpRules, 2) // 2 is UDP indicator

        var forwarderWg sync.WaitGroup

        for _, rule := range tcpRules {
                listener, err := createReusableListener("tcp", ":"+rule.srcPort)
                if err != nil {
                        log.Printf("Failed to listen on TCP port %s: %v", rule.srcPort, err)
                        continue
                }
                activeSession.addListener(listener)

                forwarderWg.Add(1)
                go func(r ForwardRule, l net.Listener) {
                        defer forwarderWg.Done()
                        startTCPForwarderWithListener(session, r, l)
                }(rule, listener)
        }

        for _, rule := range udpRules {
                addr, err := net.ResolveUDPAddr("udp", ":"+rule.srcPort)
                if err != nil {
                        log.Printf("Failed to resolve UDP address %s: %v", rule.srcPort, err)
                        continue
                }
                udpConn, err := createReusableUDPListener(addr)
                if err != nil {
                        log.Printf("Failed to listen on UDP port %s: %v", rule.srcPort, err)
                        continue
                }
                activeSession.addListener(udpConn) // Ensures cleanup on reconnect

                forwarderWg.Add(1)
                go func(r ForwardRule, c *net.UDPConn) {
                        defer forwarderWg.Done()
                        startUDPForwarderWithConn(r, c)
                }(rule, udpConn)
        }

        for !session.IsClosed() {
                time.Sleep(1 * time.Second)
        }

        forwarderWg.Wait()
        log.Printf("Session closed")
}

func startTCPForwarderWithListener(session *smux.Session, rule ForwardRule, listener net.Listener) {
        defer listener.Close()
        log.Printf("Forwarding TCP %s -> %s", rule.srcPort, rule.targetPort)

        for {
                conn, err := listener.Accept()
                if err != nil {
                        if !session.IsClosed() {
                                log.Printf("TCP accept error on %s: %v", rule.srcPort, err)
                        }
                        return
                }

                go func(c net.Conn) {
                        defer c.Close()
                        if tcpConn, ok := c.(*net.TCPConn); ok {
                                tcpConn.SetNoDelay(true)
                        }

                        stream, err := session.OpenStream()
                        if err != nil {
                                return
                        }
                        defer stream.Close()

                        header := []byte{TCP_FORWARD}
                        portBytes := []byte(rule.targetPort)
                        header = append(header, byte(len(portBytes)))
                        header = append(header, portBytes...)
                        if _, err := stream.Write(header); err != nil {
                                return
                        }

                        bidirectionalCopy(c, stream)
                }(conn)
        }
}

func bidirectionalCopy(a, b io.ReadWriteCloser) {
        var wg sync.WaitGroup
        wg.Add(2)

        copyDir := func(dst io.Writer, src io.Reader, closeOnDone io.Closer, dir string) {
                defer wg.Done()
                bufPtr := tcpPool.Get().(*[]byte)
                buf := *bufPtr
                _, err := io.CopyBuffer(dst, src, buf)
                tcpPool.Put(bufPtr)
                if err != nil && err != io.EOF {
                        log.Printf("bidirectionalCopy[%s] error: %v", dir, err)
                }
                closeOnDone.Close()
        }

        go copyDir(b, a, b, "a->b")
        go copyDir(a, b, a, "b->a")

        wg.Wait()
}

// startUDPForwarderWithConn captures public UDP traffic and ships it raw to the VPN client
func startUDPForwarderWithConn(rule ForwardRule, conn *net.UDPConn) {
        defer conn.Close()
        log.Printf("Forwarding UDP %s -> %s (RAW)", rule.srcPort, rule.targetPort)

        targetPortInt, _ := strconv.Atoi(rule.targetPort)
        targetPort16 := uint16(targetPortInt)

        buf := make([]byte, 65535) // Zero alloc reading loop
        for {
                n, clientAddr, err := conn.ReadFromUDP(buf)
                if err != nil {
                        break
                }

                addrStr := clientAddr.String()

                relayUDPSessionsMu.Lock()
                sessionID, exists := relayUDPSessions[addrStr]
                if !exists {
                        sessionID = atomic.AddUint32(&relayNextSessionID, 1)
                        relayUDPSessions[addrStr] = sessionID

                        newRelaySess := &RelayUDPSession{
                                clientAddr: clientAddr,
                                srcConn:    conn,
                        }
                        newRelaySess.lastActive.Store(time.Now().UnixNano())
                        relayUDPSessionsRev[sessionID] = newRelaySess
                } else {
                        relayUDPSessionsRev[sessionID].lastActive.Store(time.Now().UnixNano())
                }
                relayUDPSessionsMu.Unlock()

                ep := vpnEndpoint.Load()
                if ep == nil {
                        continue // VPN not yet connected via UDP tunnel
                }
                vpnAddr := ep.(*net.UDPAddr)

                // Get 14-byte frame header from Pool
                framePtr := framePool.Get().(*[]byte)
                frame := (*framePtr)[:14+n]

                binary.BigEndian.PutUint64(frame[0:8], tokenHash)
                binary.BigEndian.PutUint32(frame[8:12], sessionID)
                binary.BigEndian.PutUint16(frame[12:14], targetPort16)
                copy(frame[14:], buf[:n])

                relayUDPTunnelConn.WriteToUDP(frame, vpnAddr)

                // Safe to put back immediately because WriteToUDP blocks until payload is copied to kernel
                framePool.Put(framePtr)
        }
}

func runVPN() {
        if *strategy != "multi" && *strategy != "failover" {
                log.Fatalf("Invalid strategy '%s'. Use 'multi' or 'failover'", *strategy)
        }

        hosts := strings.Split(*host, ",")
        for i := range hosts {
                hosts[i] = strings.TrimSpace(hosts[i])
        }

        log.Printf("Configuring VPN with %d relay servers: %v", len(hosts), hosts)
        log.Printf("Strategy: %s", *strategy)

        forwardRules := *forward + "|" + *forwardudp

        manager := &RelayManager{
                relays:        make([]*RelayConnection, len(hosts)),
                token:         *token,
                forwardRules:  forwardRules,
                strategy:      *strategy,
                reconnectChan: make(chan string, len(hosts)),
        }

        for i, h := range hosts {
                manager.relays[i] = &RelayConnection{host: h}
        }

        var wg sync.WaitGroup
        for _, relay := range manager.relays {
                wg.Add(1)
                go func(r *RelayConnection) {
                        defer wg.Done()
                        manager.maintainConnection(r)
                }(relay)
        }

        go manager.monitorRelays()
        wg.Wait()
}

func (rm *RelayManager) maintainConnection(relay *RelayConnection) {
        for {
                log.Printf("[%s] Connecting to relay server...", relay.host)

                conn, err := net.DialTimeout("tcp", relay.host, 10*time.Second)
                if err != nil {
                        log.Printf("[%s] Failed to connect: %v. Retrying in 2s...", relay.host, err)
                        relay.connected.Store(false)
                        time.Sleep(2 * time.Second)
                        continue
                }

                if tcpConn, ok := conn.(*net.TCPConn); ok {
                        tcpConn.SetNoDelay(true)
                }

                conn.SetDeadline(time.Now().Add(10 * time.Second))
                if _, err := conn.Write([]byte(rm.token)); err != nil {
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }

                okBuf := make([]byte, 2)
                if _, err := io.ReadFull(conn, okBuf); err != nil || string(okBuf) != "OK" {
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }

                ruleLen := make([]byte, 2)
                binary.BigEndian.PutUint16(ruleLen, uint16(len(rm.forwardRules)))
                if _, err := conn.Write(ruleLen); err != nil {
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }
                if len(rm.forwardRules) > 0 {
                        if _, err := conn.Write([]byte(rm.forwardRules)); err != nil {
                                conn.Close()
                                time.Sleep(2 * time.Second)
                                continue
                        }
                }

                conn.SetDeadline(time.Time{})

                // --- Setup Dedicated RAW UDP Tunnel ---
                udpAddr, err := net.ResolveUDPAddr("udp", relay.host)
                if err != nil {
                        log.Printf("[%s] Failed to resolve UDP host: %v", relay.host, err)
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }
                udpTunnelConn, err := net.DialUDP("udp", nil, udpAddr)
                if err != nil {
                        log.Printf("[%s] Failed to establish UDP tunnel: %v", relay.host, err)
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }

                relay.mu.Lock()
                relay.udpTunnelConn = udpTunnelConn
                relay.udpSessions = make(map[uint32]*VPNUDPSession)
                relay.mu.Unlock()

                stopTunnel := make(chan struct{})

                // Background: UDP KeepAlive Sender
                go func() {
                        ticker := time.NewTicker(5 * time.Second)
                        defer ticker.Stop()
                        kaFrame := make([]byte, 14)
                        binary.BigEndian.PutUint64(kaFrame[0:8], tokenHash)

                        // Punch NAT hole instantly upon connection to eliminate the cold-start delay
                        udpTunnelConn.Write(kaFrame)

                        for {
                                select {
                                case <-ticker.C:
                                        udpTunnelConn.Write(kaFrame)
                                case <-stopTunnel:
                                        return
                                }
                        }
                }()

                // Background: UDP Tunnel Reader
                go rm.handleVPNUDPTunnel(relay, udpTunnelConn)

                // Background: Clean up stale VPN UDP sessions
                go func() {
                        ticker := time.NewTicker(30 * time.Second)
                        defer ticker.Stop()
                        for {
                                select {
                                case <-ticker.C:
                                        relay.udpSessionsMu.Lock()
                                        nowNano := time.Now().UnixNano()
                                        for id, sess := range relay.udpSessions {
                                                sess.mu.Lock()
                                                if time.Duration(nowNano-sess.lastActive.Load()) > 2*time.Minute && !sess.closed {
                                                        sess.closed = true
                                                        sess.conn.Close()
                                                        delete(relay.udpSessions, id)
                                                }
                                                sess.mu.Unlock()
                                        }
                                        relay.udpSessionsMu.Unlock()
                                case <-stopTunnel:
                                        return
                                }
                        }
                }()

                log.Printf("[%s] Connected and authenticated (TCP & UDP)", relay.host)

                smuxConfig := smux.DefaultConfig()
                smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
                smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
                smuxConfig.KeepAliveInterval = 10 * time.Second
                smuxConfig.KeepAliveTimeout = 30 * time.Second

                session, err := smux.Client(conn, smuxConfig)
                if err != nil {
                        close(stopTunnel)
                        udpTunnelConn.Close()
                        conn.Close()
                        time.Sleep(2 * time.Second)
                        continue
                }

                relay.mu.Lock()
                relay.conn = conn
                relay.session = session
                relay.lastCheck = time.Now()
                relay.connected.Store(true)
                relay.mu.Unlock()

                select {
                case rm.reconnectChan <- relay.host:
                default:
                }

                // Blocking call to handle TCP multiplexing
                rm.handleVPNSession(relay, session)

                // Cleanup on disconnect
                close(stopTunnel)
                udpTunnelConn.Close()

                relay.mu.Lock()
                relay.active.Store(false)
                relay.connected.Store(false)
                relay.session = nil
                relay.conn = nil
                for _, sess := range relay.udpSessions {
                        sess.mu.Lock()
                        if !sess.closed {
                                sess.closed = true
                                sess.conn.Close()
                        }
                        sess.mu.Unlock()
                }
                relay.udpSessions = nil
                relay.mu.Unlock()

                session.Close()
                conn.Close()
                log.Printf("[%s] Connection lost. Reconnecting in 2s...", relay.host)

                select {
                case rm.reconnectChan <- relay.host:
                default:
                }
                time.Sleep(2 * time.Second)
        }
}

// handleVPNUDPTunnel reads raw encapsulated UDP traffic from the Relay server
func (rm *RelayManager) handleVPNUDPTunnel(relay *RelayConnection, tunnelConn *net.UDPConn) {
        buf := make([]byte, 65535) // Zero alloc loop
        for {
                n, err := tunnelConn.Read(buf)
                if err != nil {
                        return
                }
                if n < 14 {
                        continue
                }

                auth := binary.BigEndian.Uint64(buf[0:8])
                if auth != tokenHash {
                        continue
                }

                sessionID := binary.BigEndian.Uint32(buf[8:12])
                targetPort := binary.BigEndian.Uint16(buf[12:14])

                if sessionID == 0 {
                        continue
                }

                // Failover strategy filter
                if !relay.active.Load() {
                        continue
                }

                relay.udpSessionsMu.Lock()
                sess, exists := relay.udpSessions[sessionID]
                relay.udpSessionsMu.Unlock()

                // DOUBLE-CHECK LOCKING PATCH APPLIED HERE
                if !exists {
                        addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", targetPort))
                        if err != nil {
                                continue
                        }
                        conn, err := net.DialUDP("udp", nil, addr)
                        if err != nil {
                                continue
                        }

                        newSess := &VPNUDPSession{
                                conn: conn,
                        }
                        newSess.lastActive.Store(time.Now().UnixNano())

                        relay.udpSessionsMu.Lock()
                        // DOUBLE-CHECK: Did another packet thread initialize this session while we dialed?
                        if actualSess, doubleExists := relay.udpSessions[sessionID]; doubleExists {
                                relay.udpSessionsMu.Unlock()
                                conn.Close() // Discard our redundant socket immediately to prevent FD leaks
                                sess = actualSess
                        } else {
                                relay.udpSessions[sessionID] = newSess
                                relay.udpSessionsMu.Unlock()
                                sess = newSess
                                // Only spawn the reader loop if we are the definitive winning thread
                                go rm.handleVPNUDPLocal(relay, tunnelConn, sessionID, targetPort, newSess)
                        }
                }

                sess.mu.Lock()
                if !sess.closed {
                        sess.lastActive.Store(time.Now().UnixNano())
                        sess.conn.Write(buf[14:n])
                }
                sess.mu.Unlock()
        }
}

// handleVPNUDPLocal reads from local target and encapsulates back to Relay
func (rm *RelayManager) handleVPNUDPLocal(relay *RelayConnection, tunnelConn *net.UDPConn, sessionID uint32, targetPort uint16, sess *VPNUDPSession) {
        defer func() {
                relay.udpSessionsMu.Lock()
                if v, ok := relay.udpSessions[sessionID]; ok && v == sess {
                        delete(relay.udpSessions, sessionID)
                }
                relay.udpSessionsMu.Unlock()

                sess.mu.Lock()
                sess.closed = true
                sess.conn.Close()
                sess.mu.Unlock()
        }()

        buf := make([]byte, 65535) // Zero alloc loop
        for {
                sess.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
                n, err := sess.conn.Read(buf)
                if err != nil {
                        return
                }

                framePtr := framePool.Get().(*[]byte)
                frame := (*framePtr)[:14+n]

                binary.BigEndian.PutUint64(frame[0:8], tokenHash)
                binary.BigEndian.PutUint32(frame[8:12], sessionID)
                binary.BigEndian.PutUint16(frame[12:14], targetPort)
                copy(frame[14:], buf[:n])

                tunnelConn.Write(frame)
                framePool.Put(framePtr)
        }
}

func (rm *RelayManager) monitorRelays() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()

        for {
                select {
                case <-ticker.C:
                        rm.checkAndSwitchRelay()
                case <-rm.reconnectChan:
                        rm.checkAndSwitchRelay()
                }
        }
}

func (r *RelayConnection) sessionIsClosed() bool {
        r.mu.Lock()
        defer r.mu.Unlock()
        if r.session == nil {
                return true
        }
        return r.session.IsClosed()
}

func (rm *RelayManager) checkAndSwitchRelay() {
        rm.mu.Lock()
        defer rm.mu.Unlock()

        if rm.strategy == "multi" {
                for _, relay := range rm.relays {
                        sessClosed := relay.sessionIsClosed()
                        if relay.connected.Load() && !sessClosed {
                                if !relay.active.Load() {
                                        relay.active.Store(true)
                                        log.Printf("[%s] Marked as ACTIVE (multi strategy)", relay.host)
                                }
                        } else {
                                if relay.active.Load() {
                                        relay.active.Store(false)
                                        log.Printf("[%s] Marked as INACTIVE (disconnected)", relay.host)
                                }
                        }
                }
                return
        }

        currentActive := rm.activeRelay.Load()
        var currentRelay *RelayConnection
        if currentActive != nil {
                currentRelay = currentActive.(*RelayConnection)
        }

        if currentRelay != nil && currentRelay.connected.Load() && !currentRelay.sessionIsClosed() {
                return
        }

        if currentRelay != nil {
                currentRelay.active.Store(false)
                log.Printf("[%s] Marked as inactive", currentRelay.host)
        }

        for _, relay := range rm.relays {
                if relay.connected.Load() && !relay.sessionIsClosed() {
                        relay.active.Store(true)
                        rm.activeRelay.Store(relay)
                        log.Printf("[%s] Promoted to ACTIVE relay (failover strategy)", relay.host)
                        return
                }
        }

        if currentRelay != nil {
                log.Printf("WARNING: No relay servers available, waiting for reconnection...")
        }
}

func (rm *RelayManager) handleVPNSession(relay *RelayConnection, session *smux.Session) {
        var streamWg sync.WaitGroup
        for {
                stream, err := session.AcceptStream()
                if err != nil {
                        break
                }

                streamWg.Add(1)
                go func(s *smux.Stream) {
                        defer streamWg.Done()
                        defer s.Close()

                        header := make([]byte, 2)
                        if _, err := io.ReadFull(s, header); err != nil {
                                return
                        }

                        proto := header[0]
                        portLen := header[1]
                        if portLen == 0 {
                                return
                        }
                        portBuf := make([]byte, portLen)
                        if _, err := io.ReadFull(s, portBuf); err != nil {
                                return
                        }

                        targetPort := string(portBuf)

                        if !relay.active.Load() {
                                return
                        }

                        if proto == TCP_FORWARD {
                                handleTCPStream(s, targetPort)
                        }
                }(stream)
        }
        streamWg.Wait()
}

func handleTCPStream(stream *smux.Stream, targetPort string) {
        target, err := net.DialTimeout("tcp", "127.0.0.1:"+targetPort, 5*time.Second)
        if err != nil {
                log.Printf("Failed to connect to target %s: %v", targetPort, err)
                return
        }
        defer target.Close()

        if tcpConn, ok := target.(*net.TCPConn); ok {
                tcpConn.SetNoDelay(true)
        }

        bidirectionalCopy(stream, target)
}

func parseForwardRules(rules string, proto int) []ForwardRule {
        if rules == "" {
                return nil
        }

        var result []ForwardRule
        pairs := strings.Split(rules, ";")
        for _, pair := range pairs {
                parts := strings.Split(pair, ",")
                if len(parts) == 2 {
                        src := strings.TrimSpace(parts[0])
                        tgt := strings.TrimSpace(parts[1])
                        if src == "" || tgt == "" {
                                continue
                        }
                        result = append(result, ForwardRule{
                                srcPort:    src,
                                targetPort: tgt,
                                proto:      proto,
                        })
                }
        }
        return result
}

func createReusableListener(network, address string) (net.Listener, error) {
        lc := net.ListenConfig{
                Control: func(netw, addr string, c syscall.RawConn) error {
                        var setErr error
                        c.Control(func(fd uintptr) {
                                if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
                                        setErr = err
                                }
                                _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
                        })
                        return setErr
                },
        }
        return lc.Listen(nil, network, address)
}

func createReusableUDPListener(addr *net.UDPAddr) (*net.UDPConn, error) {
        lc := net.ListenConfig{
                Control: func(netw, a string, c syscall.RawConn) error {
                        var setErr error
                        c.Control(func(fd uintptr) {
                                if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
                                        setErr = err
                                }
                                _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
                        })
                        return setErr
                },
        }
        conn, err := lc.ListenPacket(nil, "udp", addr.String())
        if err != nil {
                return nil, err
        }
        return conn.(*net.UDPConn), nil
}
