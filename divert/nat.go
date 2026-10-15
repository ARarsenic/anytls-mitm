package divert

import (
	"sync"
	"time"
)

// NATEntry represents a single NAT translation record.
type NATEntry struct {
	OriginalDst string
	UpdatedAt   time.Time
}

// NATTable is a thread-safe in-memory mapping table of
// ClientIPPort -> OriginalDstIPPort.
type NATTable struct {
	mu       sync.RWMutex
	table    map[string]*NATEntry
	ttl      time.Duration
	stopChan chan struct{}
}

// NewNATTable creates a new initialized NATTable with a default TTL.
func NewNATTable() *NATTable {
	return NewNATTableWithTTL(3 * time.Minute)
}

// NewNATTableWithTTL creates a new NATTable with the specified TTL.
func NewNATTableWithTTL(ttl time.Duration) *NATTable {
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	nt := &NATTable{
		table:    make(map[string]*NATEntry),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}
	go nt.cleanupLoop()
	return nt
}

// Set records or updates the NAT mapping: ClientIP:ClientPort -> OriginalDstIP:OriginalDstPort.
func (n *NATTable) Set(clientKey string, origDst string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.table[clientKey] = &NATEntry{
		OriginalDst: origDst,
		UpdatedAt:   time.Now(),
	}
}

// Get looks up the original destination for a given ClientIP:ClientPort.
// It verifies that the NAT mapping has not expired past the configured TTL (H-03 fix).
func (n *NATTable) Get(clientKey string) (string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.table[clientKey]
	if !ok {
		return "", false
	}
	if n.ttl > 0 && time.Since(entry.UpdatedAt) > n.ttl {
		return "", false
	}
	return entry.OriginalDst, true
}

// Delete removes an entry from the NAT table.
func (n *NATTable) Delete(clientKey string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.table, clientKey)
}

// Len returns the current number of active NAT mappings.
func (n *NATTable) Len() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.table)
}

// Stop terminates the background cleanup goroutine.
func (n *NATTable) Stop() {
	select {
	case <-n.stopChan:
		return
	default:
		close(n.stopChan)
	}
}

// cleanupLoop periodically removes NAT entries older than ttl to prevent memory growth.
func (n *NATTable) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.stopChan:
			return
		case now := <-ticker.C:
			n.mu.Lock()
			for key, entry := range n.table {
				if now.Sub(entry.UpdatedAt) > n.ttl {
					delete(n.table, key)
				}
			}
			n.mu.Unlock()
		}
	}
}
