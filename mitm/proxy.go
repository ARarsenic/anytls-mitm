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
	ListenIP     string
	ListenPort   uint16
	NATTable     *divert.NATTable
	WhitelistTTL time.Duration
	Verbose      bool
}

// Proxy implements the 3-stage MITM pipeline for intercepted hotspot traffic.
type Proxy struct {
	config     ProxyConfig
	listener   net.Listener
	natTable   *divert.NATTable
	whitelist       *WhitelistCache
	confirmedAnyTLS sync.Map
	certCloner      *CertCloner
	stopChan        chan struct{}
}

// NewProxy creates and initializes a Proxy.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	cloner, err := NewCertCloner()
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cloner: %w", err)
	}

	return &Proxy{
		config:     cfg,
		natTable:   cfg.NATTable,
		whitelist:  NewWhitelistCache(cfg.WhitelistTTL),
		certCloner: cloner,
		stopChan:   make(chan struct{}),
	}, nil
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

// Stop closes the TCP listener.
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
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()

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
		log.Printf("[Proxy] Warning: No NAT mapping found for client %s, dropping", clientAddr)
		return
	}

	log.Printf("[Proxy] Accepted TCP connection: %s -> %s", clientAddr, origDst)

	// -------------------------------------------------------------
	// Stage 1: Fail-Open Whitelist & Pre-Handshake Check
	// -------------------------------------------------------------
	if p.whitelist.Contains(origDst) {
		log.Printf("[WHITELIST-BYPASS] Client: %s -> Server: %s (Destination is in fail-open whitelist, splicing raw TCP)",
			clientAddr, origDst)
		p.relayRawTCP(clientConn, origDst, nil)
		return
	}

	// Check if initial bytes match a TLS ClientHello Record (0x16)
	brClient := bufio.NewReader(clientConn)
	headerBytes, err := brClient.Peek(5)
	if err != nil {
		log.Printf("[Proxy] Failed to peek initial bytes from %s: %v", clientAddr, err)
		return
	}

	if headerBytes[0] != 0x16 {
		log.Printf("[Stage1-PreCheck] Non-TLS record header 0x%02x from %s, bypassing MITM via raw TCP to %s",
			headerBytes[0], clientAddr, origDst)
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
				dialer := &net.Dialer{Timeout: 10 * time.Second}
				log.Printf("[Proxy-TLS] Dialing upstream TLS to %s (SNI: %q, protos: %v)...", origDst, serverName, protos)
				u, err := tls.DialWithDialer(dialer, "tcp", origDst, &tls.Config{
					ServerName:         serverName,
					InsecureSkipVerify: true,
					NextProtos:         protos,
				})
				if err != nil {
					upstreamErr = err
					log.Printf("[Proxy-TLS] Upstream TLS dial failed for %s: %v", origDst, err)
					return
				}
				upstreamTLS = u
				state := u.ConnectionState()
				log.Printf("[Proxy-TLS] Upstream TLS connected to %s | Version: 0x%04x | Cipher: 0x%04x | ALPN: %q",
					origDst, state.Version, state.CipherSuite, state.NegotiatedProtocol)
			}()
		})
	}

	serverTLSConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			clientFingerprint = AnalyzeTLSFingerprint(hello)

			// Fast Path: If certificate is already cloned and cached, return it immediately!
			if cachedCert := p.certCloner.Get(origDst); cachedCert != nil {
				log.Printf("[Proxy-Cert] Fast path: using cached certificate for %s (SNI: %q)", origDst, sni)
				startDialUpstream(sni, hello.SupportedProtos)
				return &tls.Config{
					Certificates: []tls.Certificate{*cachedCert},
				}, nil
			}

			// Slow Path (first connection only): Dial upstream synchronously to fetch & clone cert
			log.Printf("[Stage2-Cloning] First connection to %s, dialing upstream to fetch certificate (SNI: %q)...",
				origDst, sni)
			startDialUpstream(sni, hello.SupportedProtos)
			<-upstreamDone
			if upstreamErr != nil {
				log.Printf("[Stage2-Cloning] Failed to dial upstream TLS %s: %v", origDst, upstreamErr)
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

	downstreamTLS := tls.Server(wrappedClientConn, serverTLSConfig)
	handshakeErr := downstreamTLS.Handshake()
	if handshakeErr != nil {
		log.Printf("[Proxy-TLS] Downstream TLS handshake FAILED for %s -> %s: %v",
			clientAddr, origDst, handshakeErr)
		if _, isAnyTLS := p.confirmedAnyTLS.Load(origDst); !isAnyTLS {
			if isClientCertRejection(handshakeErr) {
				log.Printf("[Stage2-FailOpen] Client rejected certificate (%v), adding %s to whitelist cache for fast bypass",
					handshakeErr, origDst)
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
	// Stage 3: First-Packet AnyTLS Identification & Transparent Relay
	// -------------------------------------------------------------
	brDecrypted := bufio.NewReaderSize(downstreamTLS, 65536)
	matched, authHash, meta, err := InspectAnyTLS(brDecrypted)
	if err != nil && p.config.Verbose {
		log.Printf("[Stage3-Inspect] Read error during first packet inspection for %s -> %s: %v",
			clientAddr, origDst, err)
	}

	if matched {
		p.confirmedAnyTLS.Store(origDst, true)
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
	} else {
		log.Printf("[NON-ANYTLS-MITM] Client: %s -> Server: %s | Decrypted first packet did not match AnyTLS protocol (forwarding transparently)",
			clientAddr, origDst)
	}

	log.Printf("[Proxy-Relay] >>> Streaming started for %s <-> %s", clientAddr, origDst)

	// Transparently bridge the two decrypted TLS streams
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer uTLS.Close()
		defer downstreamTLS.Close()
		c2uBytes, c2uErr := io.Copy(uTLS, brDecrypted)
		log.Printf("[Proxy-Relay] Client -> Upstream stream ended: %s copied %d bytes, err: %v", clientAddr, c2uBytes, c2uErr)
	}()

	go func() {
		defer wg.Done()
		defer downstreamTLS.Close()
		defer uTLS.Close()
		u2cBytes, u2cErr := io.Copy(downstreamTLS, uTLS)
		log.Printf("[Proxy-Relay] Upstream -> Client stream ended: %s copied %d bytes, err: %v", clientAddr, u2cBytes, u2cErr)
	}()

	wg.Wait()
	log.Printf("[Proxy] Connection closed: %s <-> %s", clientAddr, origDst)
}

// relayRawTCP establishes a raw TCP connection to the destination and relays data.
func (p *Proxy) relayRawTCP(clientConn net.Conn, origDst string, prefixReader io.Reader) {
	log.Printf("[Proxy-RawTCP] >>> Raw TCP streaming started for %s <-> %s", clientConn.RemoteAddr(), origDst)
	upstreamConn, err := net.DialTimeout("tcp", origDst, 5*time.Second)
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
		n, err := io.Copy(upstreamConn, clientReader)
		log.Printf("[Proxy-RawTCP] Client -> Upstream stream ended: %d bytes, err: %v", n, err)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		n, err := io.Copy(clientConn, upstreamConn)
		log.Printf("[Proxy-RawTCP] Upstream -> Client stream ended: %d bytes, err: %v", n, err)
	}()

	wg.Wait()
	log.Printf("[Proxy-RawTCP] Connection closed: %s <-> %s", clientConn.RemoteAddr(), origDst)
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

