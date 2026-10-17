package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
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
	upstreamPool    *UpstreamPool
	stopChan        chan struct{}

	// Concurrency & DoS tracking (H-01 fix)
	connMu        sync.Mutex
	activeConns   int
	connsPerIP    map[string]int
	totalAccepted uint64
	totalRejected uint64

	// Fingerprint log throttling to prevent terminal spam
	loggedMu sync.Mutex
	loggedFP map[string]time.Time
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
		cfg.HandshakeTimeout = 20 * time.Second
	}
	if cfg.InspectTimeout <= 0 {
		cfg.InspectTimeout = 30 * time.Second
	}

	return &Proxy{
		config:          cfg,
		natTable:        cfg.NATTable,
		whitelist:       NewWhitelistCache(cfg.WhitelistTTL),
		confirmedAnyTLS: NewConfirmedAnyTLSCache(2000, 24*time.Hour),
		certCloner:      cloner,
		upstreamPool:    NewUpstreamPool(2, 25*time.Second),
		stopChan:        make(chan struct{}),
		connsPerIP:      make(map[string]int),
		loggedFP:        make(map[string]time.Time),
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

	p.upstreamPool.Stop()
	p.whitelist.Stop()
	p.whitelist.Clear()
	p.confirmedAnyTLS.Clear()
	p.certCloner.Clear()

	p.loggedMu.Lock()
	p.loggedFP = make(map[string]time.Time)
	p.loggedMu.Unlock()
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

	defer clientConn.Close()

	// Look up original destination from NAT table (with retry loop)
	var origDst string
	for i := 0; i < 15; i++ {
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

	// Extract original destination port to avoid accidental whitelisting of proxy ports
	_, portStr, _ := net.SplitHostPort(origDst)
	origPort, _ := strconv.Atoi(portStr)

	// -------------------------------------------------------------
	// Stage 1: AnyTLS Confirmation & Fail-Open Whitelist Check
	// -------------------------------------------------------------
	// Priority 1: If already confirmed as AnyTLS, NEVER whitelist or bypass it!
	if p.confirmedAnyTLS.Contains(origDst) {
		p.whitelist.Remove(origDst)
	} else if p.whitelist.Contains(origDst) {
		// Strictly verified standard web PKI host (e.g. apple.com:443, 223.5.5.5:443), bypass via raw TCP
		log.Printf("[WHITELIST-BYPASS] Client: %s -> Server: %s (Host in whitelist, spliced directly via Raw TCP)",
			clientAddr, origDst)
		_ = clientConn.SetDeadline(time.Time{})
		p.relayRawTCP(clientConn, origDst, nil)
		return
	}

	// Peeking initial ClientHello record header (0x16)
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

				// 1. Fast Path: Try to acquire an already-handshaked upstream connection from pool (0ms!)
				if prewarmed := p.upstreamPool.Get(origDst); prewarmed != nil {
					upstreamTLS = prewarmed
					state := prewarmed.ConnectionState()
					log.Printf("[Proxy-TLS] Acquired PRE-WARMED upstream TLS for %s (0ms dial!) | Version: 0x%04x | Cipher: 0x%04x | ALPN: %q",
						origDst, state.Version, state.CipherSuite, state.NegotiatedProtocol)
					return
				}

				// 2. Pool empty or cold target: dial on-demand
				dialer := &net.Dialer{Timeout: 15 * time.Second}
				u, err := tls.DialWithDialer(dialer, "tcp", origDst, &tls.Config{
					ServerName:         serverName,
					InsecureSkipVerify: true,
					NextProtos:         protos,
				})
				if err != nil {
					upstreamErr = err
					log.Printf("[Proxy-TLS] Upstream TLS dial failed for %s (SNI: %q, protos: %v): %v", origDst, serverName, protos, err)
					return
				}
				upstreamTLS = u
				state := u.ConnectionState()
				log.Printf("[Proxy-TLS] Upstream TLS connected to %s | Version: 0x%04x | Cipher: 0x%04x | ALPN: %q",
					origDst, state.Version, state.CipherSuite, state.NegotiatedProtocol)

				// Register target in pool so background worker keeps pre-warmed connections ready for next requests
				p.upstreamPool.RecordTarget(origDst, serverName, protos)
			}()
		})
	}

	serverTLSConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			clientFingerprint = AnalyzeTLSFingerprint(hello)
			p.upstreamPool.RecordTarget(origDst, sni, hello.SupportedProtos)

			// Fast Path: If certificate is already cloned and cached, return it immediately!
			if cachedCert, cachedProto := p.certCloner.GetWithALPN(origDst); cachedCert != nil {
				startDialUpstream(sni, hello.SupportedProtos)
				cfg := &tls.Config{
					Certificates: []tls.Certificate{*cachedCert},
				}
				if cachedProto != "" {
					cfg.NextProtos = []string{cachedProto}
				}
				return cfg, nil
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

			clonedCert, err := p.certCloner.Clone(peerCert, origDst, sni, state.NegotiatedProtocol)
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

	// Downstream TLS handshake
	_ = clientConn.SetReadDeadline(time.Now().Add(p.config.HandshakeTimeout))

	downstreamTLS := tls.Server(wrappedClientConn, serverTLSConfig)
	handshakeErr := downstreamTLS.Handshake()
	if handshakeErr != nil {
		log.Printf("[Proxy-TLS] Downstream TLS handshake FAILED for %s -> %s: %v",
			clientAddr, origDst, handshakeErr)

		// Fail-open for standard web browsing:
		// ONLY whitelist if:
		// 1. Destination is NOT already a confirmed AnyTLS server, AND
		// 2. Client sent an explicit TLS alert rejecting certificate (e.g. unknown CA, bad cert), AND
		// 3. Port is 443 (standard web) or verified strict PKI rejection
		// Network timeouts, client socket resets, and EOF are NEVER certificate rejections and will NOT whitelist!
		if !p.confirmedAnyTLS.Contains(origDst) && isClientCertRejection(handshakeErr) {
			if p.config.Verbose || origPort == 443 {
				log.Printf("[Stage2-FailOpen] Client rejected certificate with TLS alert (%v). Adding %s to whitelist for fail-open browsing",
					handshakeErr, origDst)
			}
			p.whitelist.Add(origDst)
		}

		go func() {
			<-upstreamDone
			if upstreamTLS != nil {
				upstreamTLS.Close()
			}
		}()
		return
	}

	downstreamState := downstreamTLS.ConnectionState()
	log.Printf("[Proxy-TLS] Downstream TLS handshake SUCCESS for %s -> %s | Version: 0x%04x | Cipher: 0x%04x | ALPN: %q",
		clientAddr, origDst, downstreamState.Version, downstreamState.CipherSuite, downstreamState.NegotiatedProtocol)

	// Wait for upstream connection to complete
	<-upstreamDone
	if upstreamErr != nil {
		log.Printf("[Proxy] Upstream TLS dial failed for %s: %v", origDst, upstreamErr)
		return
	}

	uTLS := upstreamTLS
	if uTLS == nil {
		log.Printf("[Proxy] Upstream TLS connection is nil for %s", origDst)
		return
	}
	defer uTLS.Close()

	// -------------------------------------------------------------
	// Stage 3: AnyTLS Identification & Transparent Relay
	// -------------------------------------------------------------
	// Clear deadlines: do NOT impose rigid timeouts that kill idle proxy connection pools
	_ = clientConn.SetDeadline(time.Time{})
	_ = uTLS.SetDeadline(time.Time{})

	brDecrypted := bufio.NewReaderSize(downstreamTLS, 65536)
	matched, authHash, meta, err := InspectAnyTLS(brDecrypted)
	if err != nil && p.config.Verbose {
		log.Printf("[Stage3-Inspect] Note on inspection for %s -> %s: %v",
			clientAddr, origDst, err)
	}

	if matched || p.confirmedAnyTLS.Contains(origDst) {
		p.confirmedAnyTLS.Add(origDst)
		p.whitelist.Remove(origDst)

		p.loggedMu.Lock()
		lastLogged, alreadyLogged := p.loggedFP[origDst]
		shouldLogDetails := !alreadyLogged || time.Since(lastLogged) > 5*time.Minute
		if shouldLogDetails {
			p.loggedFP[origDst] = time.Now()
		}
		p.loggedMu.Unlock()

		if matched {
			log.Printf("[ANYTLS-MITM-SUCCESS] Client: %s -> Server: %s | SNI: %s | AuthHash(SHA256): %x",
				clientAddr, origDst, sni, authHash)

			if shouldLogDetails {
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
		} else {
			log.Printf("[ANYTLS-MITM-SUCCESS] Client: %s -> Server: %s | SNI: %s (Subsequent AnyTLS stream)",
				clientAddr, origDst, sni)
		}
	} else if origPort == 443 {
		// ONLY whitelist port 443 (standard web browsing) when decrypted stream is plaintext HTTP!
		// Non-443 proxy ports (e.g. 8443) MUST NEVER be whitelisted!
		if !p.confirmedAnyTLS.Contains(origDst) {
			p.whitelist.Add(origDst)
			log.Printf("[WHITELIST-BYPASS] Host %s detected as standard web traffic (non-AnyTLS). Added to whitelist for direct Raw TCP bypass.", origDst)
		}
	}

	p.relayTLS(downstreamTLS, uTLS, brDecrypted, clientAddr, origDst)
}

// relayTLS transparently bridges decrypted downstream and upstream TLS streams.
func (p *Proxy) relayTLS(downstreamTLS *tls.Conn, uTLS *tls.Conn, brDecrypted *bufio.Reader, clientAddr, origDst string) {
	log.Printf("[Proxy-Relay] >>> Streaming started for %s <-> %s", clientAddr, origDst)

	var (
		c2uBytes int64
		c2uErr   error
		u2cBytes int64
		u2cErr   error
		wg       sync.WaitGroup
	)
	wg.Add(2)

	// Goroutine 1: Client -> Upstream
	go func() {
		defer wg.Done()
		defer uTLS.Close()
		defer downstreamTLS.Close()

		buf := make([]byte, 32768)
		first := true
		for {
			nr, er := brDecrypted.Read(buf)
			if nr > 0 {
				frames := DescribeAnyTLSChunk(buf[:nr], first)
				if len(frames) > 0 {
					log.Printf("[AnyTLS-Flow] [C->U %s] %s", clientAddr, strings.Join(frames, " | "))
				} else {
					log.Printf("[AnyTLS-Flow] [C->U %s] Relayed %d bytes payload", clientAddr, nr)
				}
				first = false

				nw, ew := uTLS.Write(buf[:nr])
				if nw > 0 {
					c2uBytes += int64(nw)
				}
				if ew != nil {
					c2uErr = ew
					log.Printf("[Proxy-Relay] [C->U %s] Write to upstream error: %v", clientAddr, ew)
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					c2uErr = er
					log.Printf("[Proxy-Relay] [C->U %s] Read from client error: %v", clientAddr, er)
				}
				break
			}
		}
	}()

	// Goroutine 2: Upstream -> Client
	go func() {
		defer wg.Done()
		defer downstreamTLS.Close()
		defer uTLS.Close()

		buf := make([]byte, 32768)
		for {
			nr, er := uTLS.Read(buf)
			if nr > 0 {
				frames := DescribeAnyTLSChunk(buf[:nr], false)
				if len(frames) > 0 {
					log.Printf("[AnyTLS-Flow] [U->C %s] %s", clientAddr, strings.Join(frames, " | "))
				} else {
					log.Printf("[AnyTLS-Flow] [U->C %s] Relayed %d bytes payload", clientAddr, nr)
				}

				// Write to downstream TLS in MTU-safe chunks <= 1300 bytes to avoid oversized packets / LSO drop on virtual Wi-Fi adapter
				toWrite := buf[:nr]
				for len(toWrite) > 0 {
					chunk := len(toWrite)
					if chunk > 1300 {
						chunk = 1300
					}
					nw, ew := downstreamTLS.Write(toWrite[:chunk])
					if nw > 0 {
						u2cBytes += int64(nw)
					}
					if ew != nil {
						u2cErr = ew
						log.Printf("[Proxy-Relay] [U->C %s] Write to client error: %v", clientAddr, ew)
						break
					}
					toWrite = toWrite[chunk:]
				}
				if u2cErr != nil {
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					u2cErr = er
					log.Printf("[Proxy-Relay] [U->C %s] Read from upstream error: %v", clientAddr, er)
				}
				break
			}
		}
	}()

	wg.Wait()
	log.Printf("[Proxy-Relay] <<< Stream ended for %s <-> %s | Client->Upstream: %d bytes (err: %v) | Upstream->Client: %d bytes (err: %v)",
		clientAddr, origDst, c2uBytes, c2uErr, u2cBytes, u2cErr)
}

// relayRawTCP establishes a raw TCP connection to the destination and relays data.
func (p *Proxy) relayRawTCP(clientConn net.Conn, origDst string, prefixReader io.Reader) {
	_ = clientConn.SetDeadline(time.Time{})

	upstreamConn, err := net.DialTimeout("tcp", origDst, 15*time.Second)
	if err != nil {
		log.Printf("[Proxy-RawTCP] Failed to dial raw TCP to %s: %v", origDst, err)
		return
	}
	defer upstreamConn.Close()

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
		_, _ = io.Copy(upstreamConn, clientReader)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		_, _ = io.Copy(clientConn, upstreamConn)
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
