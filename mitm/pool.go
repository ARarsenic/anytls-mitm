package mitm

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type pooledConn struct {
	conn      *tls.Conn
	createdAt time.Time
}

// UpstreamPool manages pre-warmed, active TLS connections to upstream servers.
// By maintaining a small pool of already-handshaked connections to fixed AnyTLS nodes,
// client requests can be dispatched with 0ms upstream dial latency, eliminating
// mobile Happy Eyeballs racing timeouts and connection resets on cold websites.
type UpstreamPool struct {
	mu           sync.Mutex
	pools        map[string][]*pooledConn // origDst -> slice of idle connections
	targetSNI    map[string]string        // origDst -> last known SNI
	targetProtos map[string][]string      // origDst -> last known NextProtos
	maxIdle      int
	idleTimeout  time.Duration
	stopChan     chan struct{}
}

// NewUpstreamPool initializes a new upstream connection pool.
func NewUpstreamPool(maxIdle int, idleTimeout time.Duration) *UpstreamPool {
	if maxIdle <= 0 {
		maxIdle = 2
	}
	if idleTimeout <= 0 {
		idleTimeout = 25 * time.Second
	}
	p := &UpstreamPool{
		pools:        make(map[string][]*pooledConn),
		targetSNI:    make(map[string]string),
		targetProtos: make(map[string][]string),
		maxIdle:      maxIdle,
		idleTimeout:  idleTimeout,
		stopChan:     make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

// RecordTarget registers the SNI and ALPN protocols for an origDst and triggers pre-warming.
func (p *UpstreamPool) RecordTarget(origDst, sni string, protos []string) {
	p.mu.Lock()
	p.targetSNI[origDst] = sni
	if len(protos) > 0 {
		p.targetProtos[origDst] = protos
	}
	p.mu.Unlock()

	go p.replenish(origDst)
}

// Get retrieves a pre-warmed, healthy upstream TLS connection for the given destination.
// Returns nil if no healthy pre-warmed connection is available.
func (p *UpstreamPool) Get(origDst string) *tls.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.pools[origDst]
	for len(list) > 0 {
		// Pop the most recently added connection (LIFO - freshest first)
		idx := len(list) - 1
		item := list[idx]
		list = list[:idx]
		p.pools[origDst] = list

		// Check if connection has exceeded idle timeout
		if time.Since(item.createdAt) > p.idleTimeout {
			_ = item.conn.Close()
			continue
		}

		// Health check: non-blocking read to verify socket has not received EOF / RST
		_ = item.conn.SetReadDeadline(time.Now())
		var dummy [1]byte
		_, err := item.conn.Read(dummy[:])
		_ = item.conn.SetReadDeadline(time.Time{})

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Socket is alive and clean (no pending EOF and no data)
				go p.replenish(origDst)
				return item.conn
			}
			// Connection was closed by remote server or received error
			_ = item.conn.Close()
			continue
		}

		// Received unexpected data on pre-warmed connection, discard
		_ = item.conn.Close()
	}

	go p.replenish(origDst)
	return nil
}

// replenish connects in the background to bring the pool size up to maxIdle.
func (p *UpstreamPool) replenish(origDst string) {
	p.mu.Lock()
	select {
	case <-p.stopChan:
		p.mu.Unlock()
		return
	default:
	}

	currentCount := len(p.pools[origDst])
	if currentCount >= p.maxIdle {
		p.mu.Unlock()
		return
	}

	sni := p.targetSNI[origDst]
	if sni == "" {
		p.mu.Unlock()
		return
	}
	protos := p.targetProtos[origDst]
	p.mu.Unlock()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	u, err := tls.DialWithDialer(dialer, "tcp", origDst, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         protos,
	})
	if err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.stopChan:
		_ = u.Close()
		return
	default:
	}

	if len(p.pools[origDst]) < p.maxIdle {
		p.pools[origDst] = append(p.pools[origDst], &pooledConn{
			conn:      u,
			createdAt: time.Now(),
		})
	} else {
		_ = u.Close()
	}
}

// cleanupLoop periodically evicts expired idle connections.
func (p *UpstreamPool) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.mu.Lock()
			for origDst, list := range p.pools {
				var active []*pooledConn
				for _, item := range list {
					if time.Since(item.createdAt) > p.idleTimeout {
						_ = item.conn.Close()
					} else {
						active = append(active, item)
					}
				}
				p.pools[origDst] = active
			}
			p.mu.Unlock()
		}
	}
}

// Stop closes all idle connections and terminates background maintenance.
func (p *UpstreamPool) Stop() {
	select {
	case <-p.stopChan:
		return
	default:
		close(p.stopChan)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for origDst, list := range p.pools {
		for _, item := range list {
			_ = item.conn.Close()
		}
		delete(p.pools, origDst)
	}
}
