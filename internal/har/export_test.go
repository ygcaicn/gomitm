package har

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"gomitm/internal/capture"
)

func TestEncode(t *testing.T) {
	entries := []capture.Entry{
		{
			ID:         "1",
			StartedAt:  time.Date(2026, 3, 18, 1, 0, 0, 0, time.UTC),
			DurationMs: 12,
			Method:     "GET",
			URL:        "https://example.com/api",
			ReqHeaders: map[string]string{"accept": "application/json"},
			RespStatus: 200,
			RespHeaders: map[string]string{
				"content-type": "application/json",
			},
			RespBody: `{"ok":true}`,
		},
	}

	var buf bytes.Buffer
	if err := Encode(&buf, entries); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(buf.Bytes(), &root); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	logObj, ok := root["log"].(map[string]any)
	if !ok {
		t.Fatal("missing log")
	}
	arr, ok := logObj["entries"].([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("entries invalid: %#v", logObj["entries"])
	}
}
