package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gomitm/internal/capture"
)

type fakeProvider struct {
	entries []capture.Entry
}

func (f fakeProvider) CaptureEntries() []capture.Entry {
	out := make([]capture.Entry, len(f.entries))
	copy(out, f.entries)
	return out
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
