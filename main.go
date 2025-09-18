package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smux "github.com/xtaci/smux"
)

const (
	// Optimized buffer sizes
	tcpBufferSize = 64 * 1024  // 64KB for TCP
	udpBufferSize = 4 * 1024   // 4KB for UDP (handles most packets + some batching)
	
	// Binary protocol constants
	protocolTCP = uint8(1)
	protocolUDP = uint8(2)
	
	// Binary message sizes
	protocolHeaderSize = 3 // 1 byte protocol + 2 bytes port
	
	// Sharding constants
	numShards = 64 // Must be power of 2 for efficient modulo
	shardMask = numShards - 1
	
	// Worker pool constants
	maxWorkers = 1000
	workerQueueSize = 100
	
	// Batch constants
	batchUpdateInterval = 100 * time.Millisecond
	maxBatchSize = 100
)

// Buffer pools for efficient memory reuse
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
	
	protocolHeaderPool = sync.Pool{
		New: func() interface{} {
			return &ProtocolHeader{}
		},
	}
	
	handshakePool = sync.Pool{
		New: func() interface{} {
			return &HandshakeMessage{}
		},
	}
)

// Binary protocol structures
type HandshakeMessage struct {
	Token    []byte
	TCPPorts []uint16
	UDPPorts []uint16
}

type ProtocolHeader struct {
	Protocol uint8  // 1=TCP, 2=UDP
	Port     uint16 // Port number
}

// Bandwidth limiting structures - optimized with local caching
type TokenBucket struct {
	capacity     int64         // Maximum tokens
	tokens       int64         // Current tokens (atomic)
	refillRate   int64         // Tokens per second
	lastRefill   int64         // Last refill time (atomic, unix nano)
	mu           sync.Mutex    // Protects refill operations
	localTokens  int64         // Local cache to reduce atomic operations
	localRefill  int64         // Local refill cache
}

func NewTokenBucket(bitsPerSecond int64) *TokenBucket {
	// Convert bits per second to bytes per second
	bytesPerSecond := bitsPerSecond / 8
	
	// Set capacity to allow for short bursts (1 second worth of data)
	capacity := bytesPerSecond
	if capacity < 64*1024 {
		capacity = 64 * 1024 // Minimum 64KB capacity
	}
	
	now := time.Now().UnixNano()
	return &TokenBucket{
		capacity:    capacity,
		tokens:      capacity,
		refillRate:  bytesPerSecond,
		lastRefill:  now,
		localTokens: capacity,
		localRefill: now,
	}
}

func (tb *TokenBucket) TakeTokens(amount int64) bool {
	// Try local cache first to reduce atomic operations
	if tb.localTokens >= amount {
		tb.localTokens -= amount
		return true
	}
	
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	now := time.Now().UnixNano()
	lastRefill := atomic.LoadInt64(&tb.lastRefill)
	
	// Calculate tokens to add based on time elapsed
	elapsed := now - lastRefill
	tokensToAdd := (elapsed / int64(time.Second)) * tb.refillRate
	
	if tokensToAdd > 0 {
		currentTokens := atomic.LoadInt64(&tb.tokens)
		newTokens := currentTokens + tokensToAdd
		if newTokens > tb.capacity {
			newTokens = tb.capacity
		}
		atomic.StoreInt64(&tb.tokens, newTokens)
		atomic.StoreInt64(&tb.lastRefill, now)
		
		// Update local cache
		tb.localTokens = newTokens
		tb.localRefill = now
	}
	
	if tb.localTokens >= amount {
		tb.localTokens -= amount
		atomic.AddInt64(&tb.tokens, -amount)
		return true
	}
	
	return false
}

func (tb *TokenBucket) WaitForTokens(amount int64) {
	for !tb.TakeTokens(amount) {
		// Calculate sleep time based on refill rate
		sleepTime := time.Duration((amount * int64(time.Second)) / tb.refillRate)
		if sleepTime < time.Millisecond {
			sleepTime = time.Millisecond
		} else if sleepTime > 100*time.Millisecond {
			sleepTime = 100 * time.Millisecond
		}
		time.Sleep(sleepTime)
	}
}

type ConnectionLimiter struct {
	uploadLimiter   *TokenBucket
	downloadLimiter *TokenBucket
}

func NewConnectionLimiter(bitsPerSecond int64) *ConnectionLimiter {
	return &ConnectionLimiter{
		uploadLimiter:   NewTokenBucket(bitsPerSecond),
		downloadLimiter: NewTokenBucket(bitsPerSecond),
	}
}

// Connection management configuration
var (
	// TCP settings
	tcpKeepalive       = 60 * time.Second  // TCP keepalive interval
	tcpKeepAlivePeriod = 30 * time.Second  // TCP keepalive probe interval
	tcpIdleTimeout     = 5 * time.Minute   // Close idle TCP connections after 5 minutes
	
	// UDP settings
	udpSessionTimeout  = 2 * time.Minute   // Close idle UDP sessions after 2 minutes
	udpCleanupInterval = 30 * time.Second  // How often to check for stale UDP sessions
	udpOperationTimeout = 10 * time.Second // Timeout for individual UDP operations
	
	// Session monitoring
	sessionPingInterval = 10 * time.Second // How often to check session health
	
	// Global bandwidth limit (0 = no limit)
	globalBandwidthLimit int64 = 0
)

// Global tunnel state tracking
var tunnelActive int32 // atomic: 0 = no tunnel, 1 = tunnel active

// Sharded connection tracking for better concurrency
type ConnectionShard struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionInfo
}

type ConnectionTracker struct {
	shards  [numShards]*ConnectionShard
	counter int64 // atomic counter
}

type ConnectionInfo struct {
	id        string
	conn      net.Conn
	createdAt int64 // atomic: Unix nanoseconds
	lastSeen  int64 // atomic: Unix nanoseconds
	connType  string // "tcp" or "udp"
	limiter   *ConnectionLimiter // bandwidth limiter for this connection
}

func NewConnectionTracker() *ConnectionTracker {
	ct := &ConnectionTracker{}
	for i := 0; i < numShards; i++ {
		ct.shards[i] = &ConnectionShard{
			connections: make(map[string]*ConnectionInfo),
		}
	}
	return ct
}

func (ct *ConnectionTracker) getShard(id string) *ConnectionShard {
	h := fnv.New32a()
	h.Write([]byte(id))
	return ct.shards[h.Sum32()&shardMask]
}

func (ct *ConnectionTracker) Add(conn net.Conn, connType string) string {
	id := fmt.Sprintf("%s_%d", connType, atomic.AddInt64(&ct.counter, 1))
	now := time.Now().UnixNano()
	
	var limiter *ConnectionLimiter
	if globalBandwidthLimit > 0 {
		limiter = NewConnectionLimiter(globalBandwidthLimit)
	}
	
	info := &ConnectionInfo{
		id:        id,
		conn:      conn,
		createdAt: now,
		lastSeen:  now,
		connType:  connType,
		limiter:   limiter,
	}
	
	shard := ct.getShard(id)
	shard.mu.Lock()
	shard.connections[id] = info
	shard.mu.Unlock()
	
	return id
}

func (ct *ConnectionTracker) Update(id string) {
	shard := ct.getShard(id)
	shard.mu.RLock()
	info, exists := shard.connections[id]
	shard.mu.RUnlock()
	
	if exists {
		atomic.StoreInt64(&info.lastSeen, time.Now().UnixNano())
	}
}

func (ct *ConnectionTracker) GetLimiter(id string) *ConnectionLimiter {
	shard := ct.getShard(id)
	shard.mu.RLock()
	info, exists := shard.connections[id]
	shard.mu.RUnlock()
	
	if exists {
		return info.limiter
	}
	return nil
}

func (ct *ConnectionTracker) Remove(id string) {
	shard := ct.getShard(id)
	shard.mu.Lock()
	delete(shard.connections, id)
	shard.mu.Unlock()
}

func (ct *ConnectionTracker) CleanupStale() int {
	now := time.Now().UnixNano()
	cleaned := 0
	
	for _, shard := range ct.shards {
		var toDelete []string
		var toClose []net.Conn
		
		shard.mu.RLock()
		for id, info := range shard.connections {
			lastSeen := atomic.LoadInt64(&info.lastSeen)
			var timeout time.Duration
			if info.connType == "tcp" {
				timeout = tcpIdleTimeout
			} else {
				timeout = udpSessionTimeout
			}
			
			if time.Duration(now-lastSeen) > timeout {
				toDelete = append(toDelete, id)
				toClose = append(toClose, info.conn)
				cleaned++
			}
		}
		shard.mu.RUnlock()
		
		// Close connections outside of lock
		for _, conn := range toClose {
			conn.Close()
		}
		
		// Delete stale connections
		if len(toDelete) > 0 {
			shard.mu.Lock()
			for _, id := range toDelete {
				delete(shard.connections, id)
			}
			shard.mu.Unlock()
		}
	}
	
	if cleaned > 0 {
		log.Printf("Cleaned up %d stale connections", cleaned)
	}
	
	return cleaned
}

func (ct *ConnectionTracker) Stats() (int, int) {
	tcp, udp := 0, 0
	
	for _, shard := range ct.shards {
		shard.mu.RLock()
		for _, info := range shard.connections {
			if info.connType == "tcp" {
				tcp++
			} else {
				udp++
			}
		}
		shard.mu.RUnlock()
	}
	
	return tcp, udp
}

var globalConnTracker = NewConnectionTracker()

// Worker pool for handling connections
type WorkerPool struct {
	taskQueue chan func()
	workers   int32 // atomic
	maxWorkers int32
}

func NewWorkerPool(maxWorkers int) *WorkerPool {
	wp := &WorkerPool{
		taskQueue:  make(chan func(), workerQueueSize),
		maxWorkers: int32(maxWorkers),
	}
	
	// Start initial workers
	initialWorkers := runtime.NumCPU() * 2
	if initialWorkers > maxWorkers {
		initialWorkers = maxWorkers
	}
	
	for i := 0; i < initialWorkers; i++ {
		wp.startWorker()
	}
	
	return wp
}

func (wp *WorkerPool) startWorker() {
	if atomic.LoadInt32(&wp.workers) >= wp.maxWorkers {
		return
	}
	
	atomic.AddInt32(&wp.workers, 1)
	go func() {
		defer atomic.AddInt32(&wp.workers, -1)
		
		for task := range wp.taskQueue {
			task()
		}
	}()
}

func (wp *WorkerPool) Submit(task func()) {
	select {
	case wp.taskQueue <- task:
	default:
		// Queue is full, try to start a new worker
		wp.startWorker()
		// Block until we can submit
		wp.taskQueue <- task
	}
}

func (wp *WorkerPool) Close() {
	close(wp.taskQueue)
}

var globalWorkerPool = NewWorkerPool(maxWorkers)

// UDPSession - optimized with reduced atomic operations
type UDPSession struct {
	stream      *smux.Stream
	clientAddr  *net.UDPAddr
	lastSeen    int64 // atomic: Unix nanoseconds
	cancel      context.CancelFunc
	mu          sync.RWMutex
	closed      int32 // atomic: 0 = open, 1 = closed
	connID      string
	localActive int64 // local cache for activity
}

func NewUDPSession(stream *smux.Stream, clientAddr *net.UDPAddr, connID string) *UDPSession {
	now := time.Now().UnixNano()
	return &UDPSession{
		stream:      stream,
		clientAddr:  clientAddr,
		lastSeen:    now,
		closed:      0,
		connID:      connID,
		localActive: now,
	}
}

func (us *UDPSession) UpdateActivity() {
	if atomic.LoadInt32(&us.closed) == 0 {
		now := time.Now().UnixNano()
		us.localActive = now
		// Batch update to reduce atomic operations
		if now-atomic.LoadInt64(&us.lastSeen) > int64(batchUpdateInterval) {
			atomic.StoreInt64(&us.lastSeen, now)
			globalConnTracker.Update(us.connID)
		}
	}
}

func (us *UDPSession) IsStale() bool {
	if atomic.LoadInt32(&us.closed) == 1 {
		return true
	}
	// Use local cache first
	if time.Duration(time.Now().UnixNano()-us.localActive) > udpSessionTimeout {
		lastSeen := atomic.LoadInt64(&us.lastSeen)
		return time.Duration(time.Now().UnixNano()-lastSeen) > udpSessionTimeout
	}
	return false
}

func (us *UDPSession) SetCancel(cancel context.CancelFunc) {
	us.mu.Lock()
	us.cancel = cancel
	us.mu.Unlock()
}

func (us *UDPSession) Close() {
	if atomic.CompareAndSwapInt32(&us.closed, 0, 1) {
		us.mu.Lock()
		if us.cancel != nil {
			us.cancel()
		}
		if us.stream != nil {
			us.stream.Close()
		}
		us.mu.Unlock()
		globalConnTracker.Remove(us.connID)
	}
}

func (us *UDPSession) IsClosed() bool {
	return atomic.LoadInt32(&us.closed) == 1
}

func (us *UDPSession) Write(data []byte) error {
	us.mu.RLock()
	defer us.mu.RUnlock()
	
	if atomic.LoadInt32(&us.closed) == 1 {
		return fmt.Errorf("session closed")
	}
	
	// Apply bandwidth limiting
	if limiter := globalConnTracker.GetLimiter(us.connID); limiter != nil {
		limiter.uploadLimiter.WaitForTokens(int64(len(data)))
	}
	
	// Use cached deadline setting
	us.stream.SetWriteDeadline(time.Now().Add(udpOperationTimeout))
	_, err := us.stream.Write(data)
	return err
}

// Sharded UDP forwarder for better concurrency
type UDPSessionShard struct {
	mu       sync.RWMutex
	sessions map[string]*UDPSession
}

type UDPForwarder struct {
	shards      [numShards]*UDPSessionShard
	session     *smux.Session
	mu          sync.RWMutex
	cleanupLock sync.Mutex
}

func NewUDPForwarder(session *smux.Session) *UDPForwarder {
	uf := &UDPForwarder{
		session: session,
	}
	for i := 0; i < numShards; i++ {
		uf.shards[i] = &UDPSessionShard{
			sessions: make(map[string]*UDPSession),
		}
	}
	return uf
}

func (uf *UDPForwarder) getShard(sessionKey string) *UDPSessionShard {
	h := fnv.New32a()
	h.Write([]byte(sessionKey))
	return uf.shards[h.Sum32()&shardMask]
}

func (uf *UDPForwarder) GetOrCreateSession(sessionKey string, clientAddr *net.UDPAddr, targetPort uint16) (*UDPSession, error) {
	shard := uf.getShard(sessionKey)
	
	// First try to get existing session
	shard.mu.RLock()
	if session, exists := shard.sessions[sessionKey]; exists {
		if !session.IsClosed() {
			shard.mu.RUnlock()
			return session, nil
		}
	}
	shard.mu.RUnlock()

	// Need to create new session
	uf.mu.Lock()
	defer uf.mu.Unlock()

	// Double-check after acquiring lock
	shard.mu.Lock()
	defer shard.mu.Unlock()
	
	if session, exists := shard.sessions[sessionKey]; exists {
		if !session.IsClosed() {
			return session, nil
		}
		delete(shard.sessions, sessionKey)
	}

	// Create new session
	stream, err := uf.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %v", err)
	}

	// Send binary protocol header using pool
	header := protocolHeaderPool.Get().(*ProtocolHeader)
	header.Protocol = protocolUDP
	header.Port = targetPort
	
	stream.SetWriteDeadline(time.Now().Add(udpOperationTimeout))
	_, err = stream.Write(header.Encode())
	protocolHeaderPool.Put(header)
	
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write protocol header: %v", err)
	}

	// Create a dummy connection for tracking
	dummyConn := &dummyUDPConn{addr: clientAddr}
	connID := globalConnTracker.Add(dummyConn, "udp")

	session := NewUDPSession(stream, clientAddr, connID)
	shard.sessions[sessionKey] = session

	return session, nil
}

type dummyUDPConn struct {
	addr *net.UDPAddr
}

func (d *dummyUDPConn) Read(b []byte) (n int, err error)   { return 0, fmt.Errorf("not implemented") }
func (d *dummyUDPConn) Write(b []byte) (n int, err error) { return 0, fmt.Errorf("not implemented") }
func (d *dummyUDPConn) Close() error                      { return nil }
func (d *dummyUDPConn) LocalAddr() net.Addr               { return d.addr }
func (d *dummyUDPConn) RemoteAddr() net.Addr              { return d.addr }
func (d *dummyUDPConn) SetDeadline(t time.Time) error     { return nil }
func (d *dummyUDPConn) SetReadDeadline(t time.Time) error { return nil }
func (d *dummyUDPConn) SetWriteDeadline(t time.Time) error { return nil }

func (uf *UDPForwarder) CleanupStaleSessions() int {
	uf.cleanupLock.Lock()
	defer uf.cleanupLock.Unlock()

	cleaned := 0
	for _, shard := range uf.shards {
		var toDelete []string
		var sessions []*UDPSession

		shard.mu.RLock()
		for sessionKey, session := range shard.sessions {
			if session.IsStale() {
				toDelete = append(toDelete, sessionKey)
				sessions = append(sessions, session)
			}
		}
		shard.mu.RUnlock()

		if len(toDelete) > 0 {
			// Close sessions outside of lock
			for _, session := range sessions {
				session.Close()
			}
			
			shard.mu.Lock()
			for _, key := range toDelete {
				delete(shard.sessions, key)
			}
			shard.mu.Unlock()
			
			cleaned += len(toDelete)
		}
	}

	if cleaned > 0 {
		log.Printf("Cleaned up %d stale UDP sessions", cleaned)
	}

	return cleaned
}

func (uf *UDPForwarder) Shutdown() {
	uf.cleanupLock.Lock()
	defer uf.cleanupLock.Unlock()

	totalSessions := 0
	for _, shard := range uf.shards {
		var sessions []*UDPSession
		var keys []string

		shard.mu.Lock()
		for sessionKey, session := range shard.sessions {
			keys = append(keys, sessionKey)
			sessions = append(sessions, session)
		}
		
		// Close all sessions
		for i, key := range keys {
			sessions[i].Close()
			delete(shard.sessions, key)
		}
		shard.mu.Unlock()
		
		totalSessions += len(sessions)
	}

	log.Printf("Shutdown: closed %d UDP sessions", totalSessions)
}

// Binary protocol functions - optimized
func (h *HandshakeMessage) Encode() []byte {
	buf := new(bytes.Buffer)
	buf.Grow(4 + len(h.Token) + 2 + len(h.TCPPorts)*2 + 2 + len(h.UDPPorts)*2)
	
	// Write token length and data
	binary.Write(buf, binary.BigEndian, uint32(len(h.Token)))
	buf.Write(h.Token)
	
	// Write TCP ports count and data
	binary.Write(buf, binary.BigEndian, uint16(len(h.TCPPorts)))
	for _, port := range h.TCPPorts {
		binary.Write(buf, binary.BigEndian, port)
	}
	
	// Write UDP ports count and data
	binary.Write(buf, binary.BigEndian, uint16(len(h.UDPPorts)))
	for _, port := range h.UDPPorts {
		binary.Write(buf, binary.BigEndian, port)
	}
	
	return buf.Bytes()
}

func DecodeHandshakeMessage(data []byte) (*HandshakeMessage, error) {
	buf := bytes.NewReader(data)
	msg := handshakePool.Get().(*HandshakeMessage)
	
	// Reset the message
	msg.Token = msg.Token[:0]
	msg.TCPPorts = msg.TCPPorts[:0]
	msg.UDPPorts = msg.UDPPorts[:0]
	
	// Read token
	var tokenLen uint32
	if err := binary.Read(buf, binary.BigEndian, &tokenLen); err != nil {
		handshakePool.Put(msg)
		return nil, fmt.Errorf("failed to read token length: %v", err)
	}
	
	if cap(msg.Token) < int(tokenLen) {
		msg.Token = make([]byte, tokenLen)
	} else {
		msg.Token = msg.Token[:tokenLen]
	}
	
	if _, err := io.ReadFull(buf, msg.Token); err != nil {
		handshakePool.Put(msg)
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	
	// Read TCP ports
	var tcpCount uint16
	if err := binary.Read(buf, binary.BigEndian, &tcpCount); err != nil {
		handshakePool.Put(msg)
		return nil, fmt.Errorf("failed to read TCP ports count: %v", err)
	}
	
	if cap(msg.TCPPorts) < int(tcpCount) {
		msg.TCPPorts = make([]uint16, tcpCount)
	} else {
		msg.TCPPorts = msg.TCPPorts[:tcpCount]
	}
	
	for i := range msg.TCPPorts {
		if err := binary.Read(buf, binary.BigEndian, &msg.TCPPorts[i]); err != nil {
			handshakePool.Put(msg)
			return nil, fmt.Errorf("failed to read TCP port %d: %v", i, err)
		}
	}
	
	// Read UDP ports
	var udpCount uint16
	if err := binary.Read(buf, binary.BigEndian, &udpCount); err != nil {
		handshakePool.Put(msg)
		return nil, fmt.Errorf("failed to read UDP ports count: %v", err)
	}
	
	if cap(msg.UDPPorts) < int(udpCount) {
		msg.UDPPorts = make([]uint16, udpCount)
	} else {
		msg.UDPPorts = msg.UDPPorts[:udpCount]
	}
	
	for i := range msg.UDPPorts {
		if err := binary.Read(buf, binary.BigEndian, &msg.UDPPorts[i]); err != nil {
			handshakePool.Put(msg)
			return nil, fmt.Errorf("failed to read UDP port %d: %v", i, err)
		}
	}
	
	return msg, nil
}

func (p *ProtocolHeader) Encode() []byte {
	buf := make([]byte, protocolHeaderSize)
	buf[0] = p.Protocol
	binary.BigEndian.PutUint16(buf[1:3], p.Port)
	return buf
}

func DecodeProtocolHeader(data []byte) (*ProtocolHeader, error) {
	if len(data) < protocolHeaderSize {
		return nil, fmt.Errorf("insufficient data for protocol header")
	}
	
	header := protocolHeaderPool.Get().(*ProtocolHeader)
	header.Protocol = data[0]
	header.Port = binary.BigEndian.Uint16(data[1:3])
	return header, nil
}

func parseBandwidth(bandwidthStr string) (int64, error) {
	if bandwidthStr == "" {
		return 0, nil
	}
	
	bandwidthStr = strings.ToLower(strings.TrimSpace(bandwidthStr))
	if bandwidthStr == "" {
		return 0, nil
	}
	
	var multiplier int64 = 1
	var numStr string
	
	if strings.HasSuffix(bandwidthStr, "k") {
		multiplier = 1000
		numStr = bandwidthStr[:len(bandwidthStr)-1]
	} else if strings.HasSuffix(bandwidthStr, "m") {
		multiplier = 1000000
		numStr = bandwidthStr[:len(bandwidthStr)-1]
	} else if strings.HasSuffix(bandwidthStr, "g") {
		multiplier = 1000000000
		numStr = bandwidthStr[:len(bandwidthStr)-1]
	} else {
		numStr = bandwidthStr
	}
	
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth format: %s", bandwidthStr)
	}
	
	if num <= 0 {
		return 0, fmt.Errorf("bandwidth must be positive: %s", bandwidthStr)
	}
	
	return int64(num * float64(multiplier)), nil
}

func main() {
	mode := flag.String("mode", "", "Mode: relay or vpn")
	host := flag.String("host", "", "Relay server host (used in vpn mode)")
	port := flag.String("port", "", "Port to listen on (relay) or connect to (vpn)")
	forward := flag.String("forward", "", "Local TCP ports to forward to, comma-separated (used in vpn mode)")
	forwardudp := flag.String("forwardudp", "", "Local UDP ports to forward to, comma-separated (used in vpn mode)")
	token := flag.String("token", "", "Pre-shared token required for tunnel auth (required)")
	nonat := flag.Bool("nonat", false, "Use server's public IP as source for local connections (vpn mode only)")
	limit := flag.String("limit", "", "Bandwidth limit per connection (e.g., 16m, 1g, 500k) - relay mode only")
	flag.Parse()

	if *token == "" {
		log.Fatal("You must provide -token on both sides")
	}

	// Parse bandwidth limit (only for relay mode)
	if *mode == "relay" && *limit != "" {
		var err error
		globalBandwidthLimit, err = parseBandwidth(*limit)
		if err != nil {
			log.Fatalf("Invalid bandwidth limit: %v", err)
		}
		if globalBandwidthLimit > 0 {
			log.Printf("Relay: bandwidth limit set to %d bits/second (%.2f Mbps) per connection", 
				globalBandwidthLimit, float64(globalBandwidthLimit)/1000000.0)
		}
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
		runRelay(*port, *token)
	case "vpn":
		if *host == "" || *port == "" || (*forward == "" && *forwardudp == "") {
			log.Fatal("VPN mode requires -host, -port, and at least one of -forward or -forwardudp")
		}
		runVPN(*host, *port, *forward, *forwardudp, *token, *nonat)
	default:
		log.Fatal("Invalid mode. Use -mode relay or -mode vpn")
	}
}

func configureTCPConnection(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable keepalive: %v", err)
	}
	
	if err := tcpConn.SetKeepAlivePeriod(tcpKeepalive); err != nil {
		return fmt.Errorf("failed to set keepalive period: %v", err)
	}
	
	return nil
}

func parsePorts(portList string) ([]uint16, error) {
	if portList == "" {
		return nil, nil
	}
	
	ports := strings.Split(portList, ",")
	validPorts := make([]uint16, 0, len(ports))
	
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", port)
		}
		
		validPorts = append(validPorts, uint16(portNum))
	}
	
	return validPorts, nil
}

func runRelay(listenPort, expectedToken string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Relay: failed to listen on %s: %v", listenPort, err)
	}
	log.Printf("Relay: listening for tunnel on :%s", listenPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Relay: accept error: %v", err)
			continue
		}

		if err := configureTCPConnection(conn); err != nil {
			log.Printf("Relay: failed to configure connection: %v", err)
			conn.Close()
			continue
		}

		if atomic.LoadInt32(&tunnelActive) == 1 {
			log.Printf("Relay: rejecting connection from %s - tunnel already active", conn.RemoteAddr())
			conn.Close()
			continue
		}

		log.Printf("Relay: incoming tunnel from %s", conn.RemoteAddr())
		globalWorkerPool.Submit(func() {
			handleTunnel(conn, expectedToken)
		})
	}
}

func handleTunnel(rawConn net.Conn, expectedToken string) {
	defer rawConn.Close()
	
	defer func() {
		atomic.StoreInt32(&tunnelActive, 0)
		log.Printf("Relay: tunnel closed, cleared active state")
	}()

	session, err := smux.Server(rawConn, smux.DefaultConfig())
	if err != nil {
		log.Printf("Failed to create smux server: %v", err)
		return
	}
	defer session.Close()

	controlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("Failed to accept control stream: %v", err)
		return
	}
	defer controlStream.Close()

	var msgLen uint32
	if err := binary.Read(controlStream, binary.BigEndian, &msgLen); err != nil {
		log.Printf("Failed to read handshake length: %v", err)
		return
	}
	
	handshakeData := make([]byte, msgLen)
	if _, err := io.ReadFull(controlStream, handshakeData); err != nil {
		log.Printf("Failed to read handshake data: %v", err)
		return
	}

	handshake, err := DecodeHandshakeMessage(handshakeData)
	if err != nil {
		log.Printf("Failed to decode handshake: %v", err)
		return
	}
	defer handshakePool.Put(handshake)

	if !constantTimeEqual(string(handshake.Token), expectedToken) {
		log.Printf("Relay: invalid token from %s", rawConn.RemoteAddr())
		return
	}

	if len(handshake.TCPPorts) == 0 && len(handshake.UDPPorts) == 0 {
		log.Printf("No forward ports specified")
		return
	}

	atomic.StoreInt32(&tunnelActive, 1)
	log.Printf("Relay: authenticated tunnel - TCP:%v UDP:%v", handshake.TCPPorts, handshake.UDPPorts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var listeners []net.Listener
	var udpForwarders []*UDPForwarder
	defer func() {
		log.Printf("Relay: cleaning up %d TCP listeners and %d UDP forwarders", len(listeners), len(udpForwarders))
		for _, listener := range listeners {
			listener.Close()
		}
		for _, forwarder := range udpForwarders {
			forwarder.Shutdown()
		}
	}()

	for _, port := range handshake.TCPPorts {
		portStr := fmt.Sprintf("%d", port)
		listener, err := net.Listen("tcp", ":"+portStr)
		if err != nil {
			log.Printf("Failed to listen on TCP port %d: %v", port, err)
			return
		}
		listeners = append(listeners, listener)
		log.Printf("Relay: listening on :%d for TCP clients", port)

		go func(l net.Listener, p uint16) {
			defer l.Close()
			for {
				select {
				case <-ctx.Done():
					log.Printf("Relay: TCP listener on port %d shutting down", p)
					return
				default:
				}

				clientConn, err := l.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("Relay: TCP accept error on port %d: %v", p, err)
						return
					}
				}

				if err := configureTCPConnection(clientConn); err != nil {
					log.Printf("Failed to configure client connection: %v", err)
					clientConn.Close()
					continue
				}

				globalWorkerPool.Submit(func() {
					handleClientWithContext(ctx, clientConn, p, session)
				})
			}
		}(listener, port)
	}

	for _, port := range handshake.UDPPorts {
		portStr := fmt.Sprintf("%d", port)
		udpAddr, err := net.ResolveUDPAddr("udp", ":"+portStr)
		if err != nil {
			log.Printf("Failed to resolve UDP address :%d: %v", port, err)
			return
		}
		udpListener, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Printf("Failed to listen on UDP port %d: %v", port, err)
			return
		}
		log.Printf("Relay: listening on :%d for UDP clients", port)

		udpForwarder := NewUDPForwarder(session)
		udpForwarders = append(udpForwarders, udpForwarder)
		
		go handleUDPRelayWithContext(ctx, udpListener, udpForwarder, port)
		go cleanupUDPSessionsWithContext(ctx, udpForwarder)
	}

	go func() {
		for !session.IsClosed() {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("Relay: session accept failed (%v), cancelling tunnel", err)
				cancel()
				break
			}
			
			if stream != nil {
				globalWorkerPool.Submit(func() {
					handleUnexpectedStream(stream)
				})
			}
		}
	}()

	<-ctx.Done()
	log.Printf("Relay: tunnel context cancelled, cleaning up")
}

func handleUnexpectedStream(s *smux.Stream) {
	defer s.Close()
	
	headerData := make([]byte, protocolHeaderSize)
	if _, err := io.ReadFull(s, headerData); err != nil {
		return
	}
	
	header, err := DecodeProtocolHeader(headerData)
	if err != nil {
		log.Printf("Relay: failed to decode protocol header: %v", err)
		return
	}
	defer protocolHeaderPool.Put(header)
	
	log.Printf("Relay: unexpected stream %d:%d", header.Protocol, header.Port)
}

func cleanupUDPSessionsWithContext(ctx context.Context, forwarder *UDPForwarder) {
	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			forwarder.CleanupStaleSessions()
		}
	}
}

func handleClientWithContext(ctx context.Context, clientConn net.Conn, port uint16, session *smux.Session) {
	defer clientConn.Close()

	select {
	case <-ctx.Done():
		return
	default:
	}

	connID := globalConnTracker.Add(clientConn, "tcp")
	defer globalConnTracker.Remove(connID)

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	header := protocolHeaderPool.Get().(*ProtocolHeader)
	header.Protocol = protocolTCP
	header.Port = port
	
	_, err = stream.Write(header.Encode())
	protocolHeaderPool.Put(header)
	
	if err != nil {
		log.Printf("Failed to write protocol header: %v", err)
		return
	}

	proxyPairOptimizedWithTrackingAndContext(ctx, clientConn, stream, connID)
}

func handleUDPRelayWithContext(ctx context.Context, udpListener *net.UDPConn, forwarder *UDPForwarder, targetPort uint16) {
	defer udpListener.Close()
	
	buffer := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buffer)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Relay: UDP listener on port %d shutting down", targetPort)
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
				log.Printf("UDP read error on port %d: %v", targetPort, err)
				return
			}
		}

		sessionKey := fmt.Sprintf("%s:%d", clientAddr.String(), targetPort)

		session, err := forwarder.GetOrCreateSession(sessionKey, clientAddr, targetPort)
		if err != nil {
			log.Printf("Failed to get/create UDP session: %v", err)
			continue
		}

		session.UpdateActivity()
		if err := session.Write(buffer[:n]); err != nil {
			log.Printf("Failed to write to UDP session: %v", err)
			continue
		}

		if session.cancel == nil {
			respCtx, respCancel := context.WithCancel(ctx)
			session.SetCancel(respCancel)
			
			globalWorkerPool.Submit(func() {
				handleUDPResponse(respCtx, session, udpListener, sessionKey, forwarder)
			})
		}
	}
}

func handleUDPResponse(ctx context.Context, session *UDPSession, udpListener *net.UDPConn, sessionKey string, forwarder *UDPForwarder) {
	defer func() {
		session.Close()
		shard := forwarder.getShard(sessionKey)
		shard.mu.Lock()
		delete(shard.sessions, sessionKey)
		shard.mu.Unlock()
	}()

	buffer := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buffer)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if session.IsClosed() {
			return
		}

		session.stream.SetReadDeadline(time.Now().Add(udpOperationTimeout))
		
		n, err := session.stream.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if session.IsStale() {
					return
				}
				continue
			}
			return
		}

		if limiter := globalConnTracker.GetLimiter(session.connID); limiter != nil {
			limiter.downloadLimiter.WaitForTokens(int64(n))
		}

		_, err = udpListener.WriteToUDP(buffer[:n], session.clientAddr)
		if err != nil {
			return
		}
		
		session.UpdateActivity()
	}
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

func runVPN(relayHost, relayPort, forwardPorts, forwardUDPPorts, token string, nonat bool) {
	relayAddr := net.JoinHostPort(relayHost, relayPort)

	tcpPorts, err := parsePorts(forwardPorts)
	if err != nil {
		log.Fatalf("VPN: invalid TCP forward ports: %v", err)
	}

	udpPorts, err := parsePorts(forwardUDPPorts)
	if err != nil {
		log.Fatalf("VPN: invalid UDP forward ports: %v", err)
	}

	var tcpDialer, udpDialer *net.Dialer

	if nonat {
		_, tcpDialer, udpDialer, err = setupDialers()
		if err != nil {
			log.Fatalf("VPN: failed to setup dialers: %v", err)
		}
	}

	handshake := handshakePool.Get().(*HandshakeMessage)
	handshake.Token = []byte(token)
	handshake.TCPPorts = tcpPorts
	handshake.UDPPorts = udpPorts
	handshakeData := handshake.Encode()
	handshakePool.Put(handshake)

	for {
		log.Printf("VPN: dialing relay %s", relayAddr)
		relayConn, err := net.Dial("tcp", relayAddr)
		if err != nil {
			log.Printf("VPN: failed to connect: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := configureTCPConnection(relayConn); err != nil {
			log.Printf("VPN: failed to configure relay connection: %v", err)
			relayConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		session, err := smux.Client(relayConn, smux.DefaultConfig())
		if err != nil {
			relayConn.Close()
			log.Printf("VPN: failed to create smux client: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		ctrl, err := session.OpenStream()
		if err != nil {
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to open control stream: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := binary.Write(ctrl, binary.BigEndian, uint32(len(handshakeData))); err != nil {
			ctrl.Close()
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to send handshake length: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if _, err := ctrl.Write(handshakeData); err != nil {
			ctrl.Close()
			session.Close()
			relayConn.Close()
			log.Printf("VPN: failed to send handshake: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		ctrl.Close()

		log.Printf("VPN: session established - TCP:%v UDP:%v", tcpPorts, udpPorts)

		for {
			stream, err := session.AcceptStream()
			if err != nil {
				log.Printf("VPN: session accept error: %v", err)
				break
			}
			globalWorkerPool.Submit(func() {
				handleVPNStream(stream, tcpPorts, udpPorts, tcpDialer, udpDialer)
			})
		}

		session.Close()
		relayConn.Close()
		log.Printf("VPN: session closed, will reconnect in 5 seconds")
		time.Sleep(5 * time.Second)
	}
}

func handleVPNStream(stream *smux.Stream, tcpPorts, udpPorts []uint16, tcpDialer, udpDialer *net.Dialer) {
	defer stream.Close()

	headerData := make([]byte, protocolHeaderSize)
	if _, err := io.ReadFull(stream, headerData); err != nil {
		log.Printf("VPN: failed to read protocol header: %v", err)
		return
	}

	header, err := DecodeProtocolHeader(headerData)
	if err != nil {
		log.Printf("VPN: failed to decode protocol header: %v", err)
		return
	}
	defer protocolHeaderPool.Put(header)

	if header.Protocol == protocolTCP && containsPort(tcpPorts, header.Port) {
		var localConn net.Conn
		var err error
		
		targetAddr := fmt.Sprintf("127.0.0.1:%d", header.Port)
		
		if tcpDialer != nil {
			localConn, err = tcpDialer.Dial("tcp", targetAddr)
		} else {
			localConn, err = net.Dial("tcp", targetAddr)
		}
		
		if err != nil {
			log.Printf("VPN: failed to connect to local TCP port %d: %v", header.Port, err)
			return
		}
		defer localConn.Close()

		if err := configureTCPConnection(localConn); err != nil {
			log.Printf("VPN: failed to configure local connection: %v", err)
			return
		}

		proxyPairOptimized(localConn, stream)

	} else if header.Protocol == protocolUDP && containsPort(udpPorts, header.Port) {
		targetAddr := fmt.Sprintf("127.0.0.1:%d", header.Port)
		udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			log.Printf("VPN: failed to resolve UDP address for port %d: %v", header.Port, err)
			return
		}

		var udpConn net.Conn
		
		if udpDialer != nil {
			udpConn, err = udpDialer.Dial("udp", udpAddr.String())
		} else {
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
		}
		
		if err != nil {
			log.Printf("VPN: failed to connect to local UDP port %d: %v", header.Port, err)
			return
		}
		defer udpConn.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{}, 2)

		go func() {
			defer func() { done <- struct{}{} }()
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)
			
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				stream.SetReadDeadline(time.Now().Add(udpSessionTimeout))
				
				n, err := stream.Read(buffer)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				
				udpConn.SetWriteDeadline(time.Now().Add(udpOperationTimeout))
				_, err = udpConn.Write(buffer[:n])
				if err != nil {
					return
				}
			}
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			buffer := udpBufferPool.Get().([]byte)
			defer udpBufferPool.Put(buffer)
			
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				udpConn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
				
				n, err := udpConn.Read(buffer)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				
				stream.SetWriteDeadline(time.Now().Add(udpOperationTimeout))
				_, err = stream.Write(buffer[:n])
				if err != nil {
					return
				}
			}
		}()

		<-done
		cancel()

	} else {
		log.Printf("VPN: unauthorized protocol/port: %d/%d", header.Protocol, header.Port)
	}
}

func containsPort(slice []uint16, item uint16) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func proxyPairOptimizedWithTrackingAndContext(ctx context.Context, a net.Conn, b net.Conn, connID string) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)
	limiter := globalConnTracker.GetLimiter(connID)

	// Get buffers from pool
	bufferA := tcpBufferPool.Get().([]byte)
	bufferB := tcpBufferPool.Get().([]byte)
	defer tcpBufferPool.Put(bufferA)
	defer tcpBufferPool.Put(bufferB)

	// Cache timeout value
	idleTimeout := tcpIdleTimeout
	writeTimeout := 30 * time.Second

	go func() {
		defer func() { done <- struct{}{} }()
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			a.SetReadDeadline(time.Now().Add(idleTimeout))
			
			n, err := a.Read(bufferA)
			if err != nil {
				return
			}
			
			if limiter != nil {
				limiter.uploadLimiter.WaitForTokens(int64(n))
			}
			
			globalConnTracker.Update(connID)
			
			b.SetWriteDeadline(time.Now().Add(writeTimeout))
			
			_, err = b.Write(bufferA[:n])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			b.SetReadDeadline(time.Now().Add(idleTimeout))
			
			n, err := b.Read(bufferB)
			if err != nil {
				return
			}
			
			if limiter != nil {
				limiter.downloadLimiter.WaitForTokens(int64(n))
			}
			
			globalConnTracker.Update(connID)
			
			a.SetWriteDeadline(time.Now().Add(writeTimeout))
			
			_, err = a.Write(bufferB[:n])
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func proxyPairOptimizedWithTracking(a net.Conn, b net.Conn, connID string) {
	ctx := context.Background()
	proxyPairOptimizedWithTrackingAndContext(ctx, a, b, connID)
}

func proxyPairOptimized(a net.Conn, b net.Conn) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)

	bufferA := tcpBufferPool.Get().([]byte)
	bufferB := tcpBufferPool.Get().([]byte)
	defer tcpBufferPool.Put(bufferA)
	defer tcpBufferPool.Put(bufferB)

	go func() {
		io.CopyBuffer(b, a, bufferA)
		done <- struct{}{}
	}()

	go func() {
		io.CopyBuffer(a, b, bufferB)
		done <- struct{}{}
	}()

	<-done
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
