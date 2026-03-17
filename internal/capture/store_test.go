package capture

import (
	"testing"
	"time"
)

func TestStoreRingBuffer(t *testing.T) {
	s := NewStore(2)

	s.Add(Entry{ID: "1", URL: "https://a", StartedAt: time.Now()})
	s.Add(Entry{ID: "2", URL: "https://b", StartedAt: time.Now()})
	s.Add(Entry{ID: "3", URL: "https://c", StartedAt: time.Now()})

	entries := s.Snapshot()
	if len(entries) != 2 {
		t.Fatalf("len got=%d want=2", len(entries))
	}
	if entries[0].ID != "2" || entries[1].ID != "3" {
		t.Fatalf("unexpected ids: %+v", entries)
	}
}

func TestStoreSnapshotCopy(t *testing.T) {
	s := NewStore(10)
	s.Add(Entry{
		ID: "1", URL: "https://a", StartedAt: time.Now(),
		RespHeaders:         map[string]string{"x-final": "1"},
		UpstreamRespHeaders: map[string]string{"x-upstream": "1"},
	})

	entries := s.Snapshot()
	entries[0].URL = "mutated"
	entries[0].RespHeaders["x-final"] = "mutated"
	entries[0].UpstreamRespHeaders["x-upstream"] = "mutated"

	again := s.Snapshot()
	if again[0].URL != "https://a" {
		t.Fatalf("store leaked mutation: %s", again[0].URL)
	}
	if again[0].RespHeaders["x-final"] != "1" {
		t.Fatalf("store leaked final headers mutation: %+v", again[0].RespHeaders)
	}
	if again[0].UpstreamRespHeaders["x-upstream"] != "1" {
		t.Fatalf("store leaked upstream headers mutation: %+v", again[0].UpstreamRespHeaders)
	}
}
