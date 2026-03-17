package capture

import (
	"testing"
	"time"
)

func BenchmarkStoreAdd(b *testing.B) {
	s := NewStore(10000)
	e := Entry{ID: "1", URL: "https://example.com", Method: "GET", StartedAt: time.Now()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.ID = "id"
		s.Add(e)
	}
}

func BenchmarkStoreAddParallel(b *testing.B) {
	s := NewStore(10000)
	e := Entry{ID: "1", URL: "https://example.com", Method: "GET", StartedAt: time.Now()}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Add(e)
		}
	})
}

func BenchmarkStoreSnapshot(b *testing.B) {
	s := NewStore(10000)
	for i := 0; i < 10000; i++ {
		s.Add(Entry{ID: "id", URL: "https://example.com", StartedAt: time.Now()})
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.Snapshot()
	}
}
