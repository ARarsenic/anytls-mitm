package mitm

import (
	"sync"
	"time"
)

// WhitelistCache is a thread-safe in-memory TTL cache for destinations that
// require strict TLS certificate verification (i.e. fail-open bypass).
type WhitelistCache struct {
	mu       sync.RWMutex
	entries  map[string]time.Time
	ttl      time.Duration
	stopChan chan struct{}
}

// NewWhitelistCache creates a new WhitelistCache with the given TTL.
func NewWhitelistCache(ttl time.Duration) *WhitelistCache {
	c := &WhitelistCache{
		entries:  make(map[string]time.Time),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Add adds a destination address (e.g. "IP:Port") to the whitelist with current timestamp.
func (c *WhitelistCache) Add(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[addr] = time.Now()
}

// Contains checks if the destination address is in the whitelist and not expired.
func (c *WhitelistCache) Contains(addr string) bool {
	if c.ttl <= 0 {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	addedAt, ok := c.entries[addr]
	if !ok {
		return false
	}

	if time.Since(addedAt) > c.ttl {
		return false
	}

	return true
}

// Remove explicitly removes a destination address from the whitelist.
func (c *WhitelistCache) Remove(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, addr)
}

// Clear flushes all entries from the whitelist.
func (c *WhitelistCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]time.Time)
}

// Stop cleanly terminates the background cleanup goroutine.
func (c *WhitelistCache) Stop() {
	select {
	case <-c.stopChan:
		return
	default:
		close(c.stopChan)
	}
}

// cleanupLoop periodically sweeps and removes expired entries.
func (c *WhitelistCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for addr, addedAt := range c.entries {
				if now.Sub(addedAt) > c.ttl {
					delete(c.entries, addr)
				}
			}
			c.mu.Unlock()
		}
	}
}
