package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"anytls-hotspot-mitm/divert"
)

// ProxyConfig holds parameters for the MITM proxy listener.
type ProxyConfig struct {
	ListenIP         string
	ListenPort       uint16
	NATTable         *divert.NATTable
	WhitelistTTL     time.Duration
	Verbose          bool
	MaxConns         int           // Maximum total concurrent connections (H-01)
	MaxConnsPerIP    int           // Maximum concurrent connections per client IP (H-01)
	HandshakeTimeout time.Duration // Timeout for ClientHello peek and downstream TLS handshake (H-01)
	InspectTimeout   time.Duration // Timeout for AnyTLS first-packet detection (H-01)
}

// ConfirmedAnyTLSCache provides a bounded, TTL-aware cache for confirmed AnyTLS server destinations (H-02 fix).
type ConfirmedAnyTLSCache struct {
	mu         sync.RWMutex
	entries    map[string]time.Time
	maxEntries int
	ttl        time.Duration
}

// NewConfirmedAnyTLSCache initializes a bounded, TTL-aware ConfirmedAnyTLSCache.
func NewConfirmedAnyTLSCache(maxEntries int, ttl time.Duration) *ConfirmedAnyTLSCache {
	if maxEntries <= 0 {
		maxEntries = 2000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &ConfirmedAnyTLSCache{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

// Add records an address as a confirmed AnyTLS server with current timestamp.
func (c *ConfirmedAnyTLSCache) Add(origDst string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if len(c.entries) >= c.maxEntries {
		for k, t := range c.entries {
			if now.Sub(t) > c.ttl {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxEntries {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[origDst] = now
}

// Contains checks if the address was confirmed as AnyTLS within the TTL window.
func (c *ConfirmedAnyTLSCache) Contains(origDst string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.entries[origDst]
	if !ok {
		return false
	}
	return time.Since(t) <= c.ttl
}

// Clear flushes all entries from the cache.
func (c *ConfirmedAnyTLSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]time.Time)
}

// Proxy implements the 3-stage MITM pipeline for intercepted hotspot traffic.
type Proxy struct {
	config          ProxyConfig
	listener        net.Listener
	natTable        *divert.NATTable
	whitelist       *WhitelistCache
	confirmedAnyTLS *ConfirmedAnyTLSCache
	certCloner      *CertCloner
	stopChan        chan struct{}

	// Concurrency & DoS tracking (H-01 fix)
	connMu        sync.Mutex
	activeConns   int
	connsPerIP    map[string]int
	totalAccepted uint64
	totalRejected uint64
}

// NewProxy creates and initializes a Proxy.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	cloner, err := NewCertCloner()
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cloner: %w", err)
	}

	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 2048
	}
	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = 128
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.InspectTimeout <= 0 {
		cfg.InspectTimeout = 5 * time.Second
	}

	return &Proxy{
		config:          cfg,
		natTable:        cfg.NATTable,
		whitelist:       NewWhitelistCache(cfg.WhitelistTTL),
		confirmedAnyTLS: NewConfirmedAnyTLSCache(2000, 24*time.Hour),
		certCloner:      cloner,
		stopChan:        make(chan struct{}),
		connsPerIP:      make(map[string]int),
	}, nil
}

// acquireConn attempts to register a new connection, enforcing total and per-IP limits (H-01).
func (p *Proxy) acquireConn(clientIP string) bool {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	if p.config.MaxConns > 0 && p.activeConns >= p.config.MaxConns {
		p.totalRejected++
		return false
	}
	if p.config.MaxConnsPerIP > 0 && p.connsPerIP[clientIP] >= p.config.MaxConnsPerIP {
		p.totalRejected++
		return false
	}

	p.activeConns++
	p.connsPerIP[clientIP]++
	p.totalAccepted++
	return true
}

// releaseConn decrements the active connection counts when a connection closes (H-01).
func (p *Proxy) releaseConn(clientIP string) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	p.activeConns--
	if p.activeConns < 0 {
		p.activeConns = 0
	}
	p.connsPerIP[clientIP]--
	if p.connsPerIP[clientIP] <= 0 {
		delete(p.connsPerIP, clientIP)
	}
}

// Stats returns connection metrics (H-01).
func (p *Proxy) Stats() (active int, accepted uint64, rejected uint64) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	return p.activeConns, p.totalAccepted, p.totalRejected
}

// Start begins listening on the configured address and handles incoming connections.
func (p *Proxy) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", p.config.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy listener on %s: %w", addr, err)
	}
	p.listener = ln
	log.Printf("[Proxy] Listening for intercepted hotspot traffic on 0.0.0.0:%d (targeting %s:%d)",
		p.config.ListenPort, p.config.ListenIP, p.config.ListenPort)

	go func() {
		<-ctx.Done()
		p.Stop()
	}()

	go p.acceptLoop()
	return nil
}

// Stop closes the TCP listener and terminates/cleans up background caches (H-02).
func (p *Proxy) Stop() {
	select {
	case <-p.stopChan:
		return
	default:
		close(p.stopChan)
	}

	if p.listener != nil {
		p.listener.Close()
	}

	p.whitelist.Stop()
	p.whitelist.Clear()
	p.confirmedAnyTLS.Clear()
	p.certCloner.Clear()
}

func (p *Proxy) acceptLoop() {
	for {
		clientConn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.stopChan:
				return
			default:
				log.Printf("[Proxy] Accept error: %v", err)
				return
			}
		}

		go p.handleConnection(clientConn)
	}
}

// bufferedConn wraps net.Conn to allow reading from a bufio.Reader
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	clientAddr := clientConn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	// H-01: Enforce maximum concurrency and per-client IP limits against Slowloris / DoS
	if !p.acquireConn(clientIP) {
		if p.config.Verbose {
			log.Printf("[Proxy-DoS] Connection rejected from %s: max concurrency limit reached", clientAddr)
		}
		clientConn.Close()
		return
	}
	defer p.releaseConn(clientIP)

	// H-03: Ensure clientConn is closed and NAT mapping is removed when connection finishes
	defer func() {
		clientConn.Close()
		p.natTable.Delete(clientAddr)
	}()

	// Look up original destination from NAT table (with retry loop)
	var origDst string
	for i := 0; i < 10; i++ {
		if val, found := p.natTable.Get(clientAddr); found {
			origDst = val
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if origDst == "" {
		if p.config.Verbose {
			log.Printf("[Proxy] Warning: No NAT mapping found for client %s, dropping", clientAddr)
		}
		return
	}

	if p.config.Verbose {
		log.Printf("[Proxy] Accepted TCP connection: %s -> %s", clientAddr, origDst)
	}

	// -------------------------------------------------------------
	// Stage 1: Fail-Open Whitelist & Pre-Handshake Check
	// -------------------------------------------------------------
	if p.whitelist.Contains(origDst) {
		if p.config.Verbose {
			log.Printf("[Stage1-Whitelist-Bypass] Client: %s -> Server: %s (Destination is in fail-open whitelist, splicing raw TCP)",
				clientAddr, origDst)
		}
		_ = clientConn.SetDeadline(time.Time{})
		p.relayRawTCP(clientConn, origDst, nil)
		return
	}

	// H-01: Set read deadline for initial ClientHello record peek
	_ = clientConn.SetReadDeadline(time.Now().Add(p.config.HandshakeTimeout))

	brClient := bufio.NewReader(clientConn)
	headerBytes, err := brClient.Peek(5)
	if err != nil {
		if p.config.Verbose {
			log.Printf("[Proxy] Failed to peek initial bytes from %s: %v", clientAddr, err)
		}
		return
	}

	if headerBytes[0] != 0x16 {
		if p.config.Verbose {
			log.Printf("[Stage1-PreCheck] Non-TLS record header 0x%02x from %s, bypassing MITM via raw TCP to %s",
				headerBytes[0], clientAddr, origDst)
		}
		_ = clientConn.SetDeadline(time.Time{})
		p.relayRawTCP(clientConn, origDst, brClient)
		return
	}

	// -------------------------------------------------------------
	// Stage 2: Dynamic Certificate Cloning & Handshake Probing
	// -------------------------------------------------------------
	wrappedClientConn := &bufferedConn{
		Conn: clientConn,
		r:    brClient,
	}

	var (
		upstreamTLS       *tls.Conn
		upstreamErr       error
		upstreamDone      = make(chan struct{})
		sni               string
		clientFingerprint *TLSFingerprintInfo
		dialOnce          sync.Once
	)

	startDialUpstream := func(serverName string, protos []string) {
		dialOnce.Do(func() {
			go func() {
				defer close(upstreamDone)
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				u, err := tls.DialWithDialer(dialer, "tcp", origDst, &tls.Config{
					ServerName:         serverName,
					InsecureSkipVerify: true,
					NextProtos:         protos,
				})
				if err != nil {
					upstreamErr = err
					return
				}
				upstreamTLS = u
			}()
		})
	}

	serverTLSConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			clientFingerprint = AnalyzeTLSFingerprint(hello)

			// Fast Path: If certificate is already cloned and cached, return it immediately!
			if cachedCert := p.certCloner.Get(origDst); cachedCert != nil {
				startDialUpstream(sni, hello.SupportedProtos)
				return &tls.Config{
					Certificates: []tls.Certificate{*cachedCert},
				}, nil
			}

			// Slow Path (first connection only): Dial upstream synchronously to fetch & clone cert
			if p.config.Verbose {
				log.Printf("[Stage2-Cloning] First connection to %s, dialing upstream to fetch certificate (SNI: %q)...",
					origDst, sni)
			}
			startDialUpstream(sni, hello.SupportedProtos)
			<-upstreamDone
			if upstreamErr != nil {
				if p.config.Verbose {
					log.Printf("[Stage2-Cloning] Failed to dial upstream TLS %s: %v", origDst, upstreamErr)
				}
				return nil, fmt.Errorf("upstream tls dial failed to %s: %w", origDst, upstreamErr)
			}

			state := upstreamTLS.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				if p.config.Verbose {
					log.Printf("[Stage2-Cloning] Upstream %s did not provide any peer certificates", origDst)
				}
				return nil, fmt.Errorf("no peer certificates presented by upstream %s", origDst)
			}

			peerCert := state.PeerCertificates[0]
			if p.config.Verbose {
				log.Printf("[Stage2-Cloning] Upstream TLS connected. Cert Subject: %q, Issuer: %q, DNS: %v. Generating 1:1 clone...",
					peerCert.Subject, peerCert.Issuer, peerCert.DNSNames)
			}

			clonedCert, err := p.certCloner.Clone(peerCert, origDst, sni)
			if err != nil {
				if p.config.Verbose {
					log.Printf("[Stage2-Cloning] Certificate cloning failed: %v", err)
				}
				return nil, fmt.Errorf("certificate cloning failed: %w", err)
			}

			cfg := &tls.Config{
				Certificates: []tls.Certificate{*clonedCert},
			}
			if state.NegotiatedProtocol != "" {
				cfg.NextProtos = []string{state.NegotiatedProtocol}
			}

			return cfg, nil
		},
	}

	// H-01: Set read deadline for downstream TLS handshake
	_ = clientConn.SetReadDeadline(time.Now().Add(p.config.HandshakeTimeout))

	downstreamTLS := tls.Server(wrappedClientConn, serverTLSConfig)
	handshakeErr := downstreamTLS.Handshake()
	if handshakeErr != nil {
		// Handshake failed (e.g. client strict verification rejected cloned cert)
		if p.config.Verbose {
			log.Printf("[Stage2-FailOpen] Downstream TLS handshake failed for %s -> %s: %v",
				clientAddr, origDst, handshakeErr)
		}
		if !p.confirmedAnyTLS.Contains(origDst) {
			if isClientCertRejection(handshakeErr) {
				if p.config.Verbose {
					log.Printf("[Stage2-FailOpen] Client rejected certificate (%v), adding %s to whitelist cache for fast bypass",
						handshakeErr, origDst)
				}
				p.whitelist.Add(origDst)
			} else if p.config.Verbose {
				log.Printf("[Stage2-FailOpen] Handshake error was network/reset (%v), NOT certificate rejection. Will NOT whitelist %s",
					handshakeErr, origDst)
			}
		} else if p.config.Verbose {
			log.Printf("[Stage2-FailOpen] Not whitelisting %s because it is a confirmed AnyTLS server", origDst)
		}

		go func() {
			<-upstreamDone
			if upstreamTLS != nil {
				upstreamTLS.Close()
			}
		}()
		return
	}

	if p.config.Verbose {
		log.Printf("[Stage2-Success] Downstream TLS handshake SUCCESS for %s -> %s! Client accepted cloned certificate.",
			clientAddr, origDst)
	}

	// Wait for upstream connection to complete
	<-upstreamDone
	if upstreamErr != nil {
		if p.config.Verbose {
			log.Printf("[Proxy] Upstream TLS dial failed for %s: %v", origDst, upstreamErr)
		}
		return
	}

	uTLS := upstreamTLS
	if uTLS == nil {
		if p.config.Verbose {
			log.Printf("[Proxy] Upstream TLS connection is nil for %s", origDst)
		}
		return
	}
	defer uTLS.Close()

	// -------------------------------------------------------------
	// Stage 3: First-Packet AnyTLS Identification & Transparent Relay
	// -------------------------------------------------------------
	// H-01: Set read deadline for first-packet inspection against Slowloris
	_ = clientConn.SetReadDeadline(time.Now().Add(p.config.InspectTimeout))

	brDecrypted := bufio.NewReaderSize(downstreamTLS, 65536)
	matched, authHash, meta, err := InspectAnyTLS(brDecrypted)
	if err != nil && p.config.Verbose {
		log.Printf("[Stage3-Inspect] Read error during first packet inspection for %s -> %s: %v",
			clientAddr, origDst, err)
	}

	if matched {
		p.confirmedAnyTLS.Add(origDst)
		p.whitelist.Remove(origDst)
		log.Printf("[ANYTLS-MITM-SUCCESS] Client: %s -> Server: %s | SNI: %s | AuthHash(SHA256): %x",
			clientAddr, origDst, sni, authHash)

		// Display Client Fingerprint & Session Metadata info
		var fpDetails []string
		if clientFingerprint != nil {
			fpDetails = append(fpDetails, fmt.Sprintf("TLS-Fingerprint: %s", clientFingerprint.FingerprintType))
			if clientFingerprint.HasGREASE {
				fpDetails = append(fpDetails, "GREASE=True")
			}
			if len(clientFingerprint.ALPN) > 0 {
				fpDetails = append(fpDetails, fmt.Sprintf("ALPN=%v", clientFingerprint.ALPN))
			}
			if clientFingerprint.JA3Hash != "" {
				fpDetails = append(fpDetails, fmt.Sprintf("JA3=%s", clientFingerprint.JA3Hash))
			}
		}
		if meta != nil && meta.ClientApp != "" {
			fpDetails = append(fpDetails, fmt.Sprintf("ClientApp: %q", meta.ClientApp))
		}
		if meta != nil && meta.Version != "" {
			fpDetails = append(fpDetails, fmt.Sprintf("Ver: %s", meta.Version))
		}
		if meta != nil && meta.PaddingMD5 != "" {
			fpDetails = append(fpDetails, fmt.Sprintf("PaddingMD5: %s", meta.PaddingMD5))
		}
		if len(fpDetails) > 0 {
			log.Printf("[ANYTLS-FINGERPRINT]  %s", strings.Join(fpDetails, " | "))
		}
	}

	// H-01: Clear deadlines before entering transparent stream relay
	_ = clientConn.SetDeadline(time.Time{})
	_ = uTLS.SetDeadline(time.Time{})

	p.relayTLS(downstreamTLS, uTLS, brDecrypted, clientAddr, origDst)
}

// relayTLS transparently bridges decrypted downstream and upstream TLS streams.
func (p *Proxy) relayTLS(downstreamTLS *tls.Conn, uTLS *tls.Conn, brDecrypted *bufio.Reader, clientAddr, origDst string) {
	// Enable TCP Keep-Alive if underlying sockets allow
	if tcp, ok := uTLS.NetConn().(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer uTLS.Close()
		defer downstreamTLS.Close()
		c2uBytes, c2uErr := io.Copy(uTLS, brDecrypted)
		if p.config.Verbose {
			log.Printf("[Proxy-Relay] Client -> Upstream stream ended: copied %d bytes, err: %v", c2uBytes, c2uErr)
		}
	}()

	go func() {
		defer wg.Done()
		defer downstreamTLS.Close()
		defer uTLS.Close()
		u2cBytes, u2cErr := io.Copy(downstreamTLS, uTLS)
		if p.config.Verbose {
			log.Printf("[Proxy-Relay] Upstream -> Client stream ended: copied %d bytes, err: %v", u2cBytes, u2cErr)
		}
	}()

	wg.Wait()
	if p.config.Verbose {
		log.Printf("[Proxy] Connection closed: %s <-> %s", clientAddr, origDst)
	}
}

// relayRawTCP establishes a raw TCP connection to the destination and relays data.
func (p *Proxy) relayRawTCP(clientConn net.Conn, origDst string, prefixReader io.Reader) {
	_ = clientConn.SetDeadline(time.Time{})

	upstreamConn, err := net.DialTimeout("tcp", origDst, 5*time.Second)
	if err != nil {
		if p.config.Verbose {
			log.Printf("[Proxy-RawTCP] Failed to dial raw TCP to %s: %v", origDst, err)
		}
		return
	}
	defer upstreamConn.Close()

	if tcp, ok := clientConn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcp, ok := upstreamConn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	var clientReader io.Reader = clientConn
	if prefixReader != nil {
		clientReader = prefixReader
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer upstreamConn.Close()
		defer clientConn.Close()
		n, err := io.Copy(upstreamConn, clientReader)
		if p.config.Verbose {
			log.Printf("[Proxy-RawTCP] Client -> Upstream stream ended: %d bytes, err: %v", n, err)
		}
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		n, err := io.Copy(clientConn, upstreamConn)
		if p.config.Verbose {
			log.Printf("[Proxy-RawTCP] Upstream -> Client stream ended: %d bytes, err: %v", n, err)
		}
	}()

	wg.Wait()
	if p.config.Verbose {
		log.Printf("[Proxy-RawTCP] Connection closed: %s <-> %s", clientConn.RemoteAddr(), origDst)
	}
}

// isClientCertRejection checks if the TLS handshake error indicates that the client
// actively rejected the cloned certificate with an explicit TLS alert (strict cert verification / pinning).
// Network timeouts, client socket resets (wsarecv/RST), and EOF are NOT certificate rejections.
func isClientCertRejection(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// In Go crypto/tls, client alerts are surfaced as "remote error: tls: ..."
	if strings.Contains(s, "remote error: tls:") {
		return strings.Contains(s, "bad certificate") ||
			strings.Contains(s, "unknown certificate authority") ||
			strings.Contains(s, "certificate revoked") ||
			strings.Contains(s, "certificate expired") ||
			strings.Contains(s, "certificate unknown") ||
			strings.Contains(s, "unsupported certificate") ||
			strings.Contains(s, "handshake failure")
	}
	return false
}
