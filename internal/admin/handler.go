package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"gomitm/internal/capture"
	"gomitm/internal/har"
)

type CaptureProvider interface {
	CaptureEntries() []capture.Entry
}

type Handler struct {
	provider CaptureProvider
}

func NewHandler(provider CaptureProvider) http.Handler {
	h := &Handler{provider: provider}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/api/captures", h.captures)
	mux.HandleFunc("/api/captures.har", h.capturesHAR)
	return mux
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
