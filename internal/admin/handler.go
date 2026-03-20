package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gomitm/internal/capture"
	"gomitm/internal/har"
	srvstats "gomitm/internal/server"
)

type CaptureProvider interface {
	CaptureEntries() []capture.Entry
}

type Handler struct {
	provider    CaptureProvider
	bearerToken string
}

type Options struct {
	BearerToken string
}

func NewHandler(provider CaptureProvider, opts ...Options) http.Handler {
	h := &Handler{provider: provider}
	if len(opts) > 0 {
		h.bearerToken = strings.TrimSpace(opts[0].BearerToken)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/api/stats", h.stats)
	mux.HandleFunc("/api/metrics", h.metrics)
	mux.HandleFunc("/api/captures", h.captures)
	mux.HandleFunc("/api/captures.har", h.capturesHAR)
	return h.wrapAuth(mux)
}

func (h *Handler) wrapAuth(next http.Handler) http.Handler {
	token := strings.TrimSpace(h.bearerToken)
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimSpace(r.Header.Get("Authorization"))
		if !matchBearerToken(got, token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func matchBearerToken(gotAuthHeader, expectedToken string) bool {
	if strings.TrimSpace(expectedToken) == "" {
		return true
	}
	expected := "Bearer " + expectedToken
	gotBytes := []byte(gotAuthHeader)
	expectedBytes := []byte(expected)
	if len(gotBytes) != len(expectedBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(gotBytes, expectedBytes) == 1
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) captures(w http.ResponseWriter, r *http.Request) {
	entries := h.getEntries()
	limit := parsePositiveInt(r.URL.Query().Get("limit"))
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handler) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.getStats())
}

func (h *Handler) metrics(w http.ResponseWriter, _ *http.Request) {
	stats := h.getStats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "gomitm_conn_active %d\n", stats.Conn.ActiveConns)
	_, _ = fmt.Fprintf(w, "gomitm_conn_total %d\n", stats.Conn.TotalConns)
	_, _ = fmt.Fprintf(w, "gomitm_conn_limit_drop_total %d\n", stats.Conn.LimitDrop)
	_, _ = fmt.Fprintf(w, "gomitm_udp_sessions_active %d\n", stats.UDP.ActiveSessions)
	_, _ = fmt.Fprintf(w, "gomitm_udp_sessions_total %d\n", stats.UDP.TotalSessions)
	_, _ = fmt.Fprintf(w, "gomitm_udp_session_limit_drop_total %d\n", stats.UDP.LimitDrop)
	_, _ = fmt.Fprintf(w, "gomitm_udp_packets_in_total %d\n", stats.UDP.PacketsIn)
	_, _ = fmt.Fprintf(w, "gomitm_udp_packets_out_total %d\n", stats.UDP.PacketsOut)
	_, _ = fmt.Fprintf(w, "gomitm_udp_packets_drop_total %d\n", stats.UDP.PacketsDrop)
	_, _ = fmt.Fprintf(w, "gomitm_udp_policy_reject_total %d\n", stats.UDP.PolicyReject)
	_, _ = fmt.Fprintf(w, "gomitm_udp_parse_error_total %d\n", stats.UDP.ParseError)
	_, _ = fmt.Fprintf(w, "gomitm_udp_fragment_drop_total %d\n", stats.UDP.FragmentDrop)
	if stats.MITM.FailOpenEnabled {
		_, _ = fmt.Fprintf(w, "gomitm_mitm_fail_open_enabled 1\n")
	} else {
		_, _ = fmt.Fprintf(w, "gomitm_mitm_fail_open_enabled 0\n")
	}
	_, _ = fmt.Fprintf(w, "gomitm_mitm_fail_open_learned_total %d\n", stats.MITM.FailOpenLearned)
	_, _ = fmt.Fprintf(w, "gomitm_mitm_learned_bypass_hosts %d\n", stats.MITM.LearnedBypass)
}

func (h *Handler) capturesHAR(w http.ResponseWriter, _ *http.Request) {
	entries := h.getEntries()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := har.Encode(w, entries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) getEntries() []capture.Entry {
	if h == nil || h.provider == nil {
		return nil
	}
	return h.provider.CaptureEntries()
}

func (h *Handler) getStats() srvstats.Stats {
	if h == nil || h.provider == nil {
		return srvstats.Stats{}
	}
	if p, ok := h.provider.(interface{ Stats() srvstats.Stats }); ok {
		return p.Stats()
	}
	return srvstats.Stats{}
}

func parsePositiveInt(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
