package capture

import (
	"sync"
	"time"
)

type Config struct {
	Enabled      bool
	MaxEntries   int
	MaxBodyBytes int64
	ContentTypes []string
}

type Entry struct {
	ID         string
	StartedAt  time.Time
	DurationMs int64
	Method     string
	URL        string

	ReqHeaders map[string]string
	ReqBody    string

	RespStatus  int
	RespHeaders map[string]string
	RespBody    string

	Rule  string
	Error string
}

type Store struct {
	mu      sync.RWMutex
	maxSize int
	entries []Entry
}

func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Store{maxSize: maxSize, entries: make([]Entry, 0, maxSize)}
}

func (s *Store) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e = cloneEntry(e)
	if len(s.entries) < s.maxSize {
		s.entries = append(s.entries, e)
		return
	}
	copy(s.entries[0:], s.entries[1:])
	s.entries[len(s.entries)-1] = e
}

func (s *Store) Snapshot() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Entry, len(s.entries))
	for i := range s.entries {
		out[i] = cloneEntry(s.entries[i])
	}
	return out
}

func cloneEntry(e Entry) Entry {
	out := e
	if e.ReqHeaders != nil {
		out.ReqHeaders = cloneMap(e.ReqHeaders)
	}
	if e.RespHeaders != nil {
		out.RespHeaders = cloneMap(e.RespHeaders)
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
