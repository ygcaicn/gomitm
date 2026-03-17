package har

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gomitm/internal/capture"
)

type harRoot struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            int64          `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           map[string]any `json:"cache"`
	Timings         harTimings     `json:"timings"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Cookies     []any       `json:"cookies"`
	QueryString []any       `json:"queryString"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Cookies     []any       `json:"cookies"`
	Content     harContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harTimings struct {
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
}

func Encode(w io.Writer, entries []capture.Entry) error {
	if w == nil {
		return fmt.Errorf("nil writer")
	}

	harEntries := make([]harEntry, 0, len(entries))
	for _, e := range entries {
		h := harEntry{
			StartedDateTime: e.StartedAt.UTC().Format(time.RFC3339Nano),
			Time:            e.DurationMs,
			Request: harRequest{
				Method:      defaultString(e.Method, http.MethodGet),
				URL:         e.URL,
				HTTPVersion: "HTTP/1.1",
				Headers:     mapToHeaders(e.ReqHeaders),
				Cookies:     []any{},
				QueryString: []any{},
				HeadersSize: -1,
				BodySize:    len(e.ReqBody),
			},
			Response: harResponse{
				Status:      e.RespStatus,
				StatusText:  http.StatusText(e.RespStatus),
				HTTPVersion: "HTTP/1.1",
				Headers:     mapToHeaders(e.RespHeaders),
				Cookies:     []any{},
				Content: harContent{
					Size:     len(e.RespBody),
					MimeType: mimeFromHeaders(e.RespHeaders),
					Text:     e.RespBody,
				},
				HeadersSize: -1,
				BodySize:    len(e.RespBody),
			},
			Cache: map[string]any{},
			Timings: harTimings{
				Send:    -1,
				Wait:    e.DurationMs,
				Receive: -1,
			},
		}
		harEntries = append(harEntries, h)
	}

	root := harRoot{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{Name: "gomitm", Version: "0.1.0"},
			Entries: harEntries,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

func ExportToFile(path string, entries []capture.Entry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()
	return Encode(f, entries)
}

func mapToHeaders(h map[string]string) []harHeader {
	if len(h) == 0 {
		return []harHeader{}
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]harHeader, 0, len(keys))
	for _, k := range keys {
		out = append(out, harHeader{Name: k, Value: h[k]})
	}
	return out
}

func mimeFromHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	for k, v := range h {
		if strings.EqualFold(k, "content-type") {
			return v
		}
	}
	return ""
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
