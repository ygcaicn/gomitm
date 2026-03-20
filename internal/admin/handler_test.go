package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gomitm/internal/capture"
	srvstats "gomitm/internal/server"
)

type fakeProvider struct {
	entries []capture.Entry
	stats   srvstats.Stats
}

func (f fakeProvider) CaptureEntries() []capture.Entry {
	out := make([]capture.Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

func (f fakeProvider) Stats() srvstats.Stats {
	return f.stats
}

func TestHealthz(t *testing.T) {
	h := NewHandler(fakeProvider{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status got=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestCapturesLimit(t *testing.T) {
	h := NewHandler(fakeProvider{entries: []capture.Entry{
		{ID: "1", URL: "https://a", StartedAt: time.Now()},
		{ID: "2", URL: "https://b", StartedAt: time.Now()},
		{ID: "3", URL: "https://c", StartedAt: time.Now()},
	}})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/captures?limit=2", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status got=%d", rr.Code)
	}
	var arr []capture.Entry
	if err := json.Unmarshal(rr.Body.Bytes(), &arr); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("len got=%d want=2", len(arr))
	}
}

func TestCapturesHAR(t *testing.T) {
	h := NewHandler(fakeProvider{entries: []capture.Entry{
		{ID: "1", URL: "https://a", Method: "GET", RespStatus: 200, StartedAt: time.Now()},
	}})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/captures.har", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status got=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type got=%q", ct)
	}
	if !strings.Contains(rr.Body.String(), `"log"`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestStats(t *testing.T) {
	h := NewHandler(fakeProvider{
		stats: srvstats.Stats{
			UDP: srvstats.UDPStats{
				ActiveSessions: 2,
				PacketsDrop:    3,
			},
		},
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status got=%d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"udp"`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"active_sessions":2`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestAdminBearerAuth(t *testing.T) {
	h := NewHandler(fakeProvider{
		stats: srvstats.Stats{
			UDP: srvstats.UDPStats{ActiveSessions: 1},
		},
	}, Options{
		BearerToken: "secret-token",
	})

	// healthz is intentionally kept open for local probes.
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("healthz status got=%d", rr.Code)
		}
	}

	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized status got=%d", rr.Code)
		}
	}

	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong token status got=%d", rr.Code)
		}
	}

	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("authorized status got=%d", rr.Code)
		}
	}

	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("authorized metrics status got=%d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "gomitm_udp_sessions_active") {
			t.Fatalf("unexpected metrics body: %s", rr.Body.String())
		}
	}
}

func TestMetrics(t *testing.T) {
	h := NewHandler(fakeProvider{
		stats: srvstats.Stats{
			Conn: srvstats.ConnStats{
				ActiveConns: 4,
				TotalConns:  10,
				LimitDrop:   1,
			},
			UDP: srvstats.UDPStats{
				ActiveSessions: 2,
				TotalSessions:  7,
				PacketsIn:      9,
			},
			MITM: srvstats.MITMStats{
				FailOpenEnabled: true,
				FailOpenLearned: 3,
				LearnedBypass:   1,
			},
		},
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status got=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content-type got=%q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "gomitm_conn_active 4") {
		t.Fatalf("unexpected metrics body: %s", body)
	}
	if !strings.Contains(body, "gomitm_udp_sessions_active 2") {
		t.Fatalf("unexpected metrics body: %s", body)
	}
	if !strings.Contains(body, "gomitm_mitm_fail_open_enabled 1") {
		t.Fatalf("unexpected metrics body: %s", body)
	}
}
