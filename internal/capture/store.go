package capture

import (
	"sync"
	"time"
)

type Config struct {
	Enabled          bool
	MaxEntries       int
	MaxBodyBytes     int64
	ContentTypes     []string
	RedactHeaders    []string
	RedactJSONFields []string
}

type Entry struct {
	ID         string
	StartedAt  time.Time
	DurationMs int64
	Method     string
	URL        string

	ReqHeaders map[string]string
	ReqBody    string

	UpstreamRespStatus  int
	UpstreamRespHeaders map[string]string
	UpstreamRespBody    string

	RespStatus   int
	RespHeaders  map[string]string
	RespBody     string
	RespModified bool

	Rule  string
	Error string
}

type Store struct {
	mu      sync.RWMutex
	maxSize int
	entries []Entry
	start   int
	size    int
}

func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Store{
		maxSize: maxSize,
		entries: make([]Entry, maxSize),
	}
}

func (s *Store) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e = cloneEntry(e)
	if s.size < s.maxSize {
		idx := (s.start + s.size) % s.maxSize
		s.entries[idx] = e
		s.size++
		return
	}
	s.entries[s.start] = e
	s.start = (s.start + 1) % s.maxSize
}

func (s *Store) Snapshot() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Entry, s.size)
	for i := 0; i < s.size; i++ {
		idx := (s.start + i) % s.maxSize
		out[i] = cloneEntry(s.entries[idx])
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
	if e.UpstreamRespHeaders != nil {
		out.UpstreamRespHeaders = cloneMap(e.UpstreamRespHeaders)
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
