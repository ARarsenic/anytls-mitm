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
	mu    sync.RWMutex
	table map[string]*NATEntry
}

// NewNATTable creates a new initialized NATTable.
func NewNATTable() *NATTable {
	nt := &NATTable{
		table: make(map[string]*NATEntry),
	}
	go nt.cleanupLoop(10 * time.Minute)
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
func (n *NATTable) Get(clientKey string) (string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.table[clientKey]
	if !ok {
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

// cleanupLoop periodically removes NAT entries older than ttl to prevent memory growth.
func (n *NATTable) cleanupLoop(ttl time.Duration) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for now := range ticker.C {
		n.mu.Lock()
		for key, entry := range n.table {
			if now.Sub(entry.UpdatedAt) > ttl {
				delete(n.table, key)
			}
		}
		n.mu.Unlock()
	}
}
