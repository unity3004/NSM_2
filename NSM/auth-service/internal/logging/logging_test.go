package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNew_RejectsInvalidLevel(t *testing.T) {
	if _, err := New("not-a-level", "json", "development", "auth-service"); err == nil {
		t.Error("New() with an invalid level = nil error, want one")
	}
}

func TestNew_EmitsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.InfoLevel,
	))

	logger.Info("test event", zap.String("request_id", "req_123"))

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("log output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if decoded["request_id"] != "req_123" {
		t.Errorf("decoded[\"request_id\"] = %v, want %q", decoded["request_id"], "req_123")
	}
	if decoded["msg"] != "test event" {
		t.Errorf("decoded[\"msg\"] = %v, want %q", decoded["msg"], "test event")
	}
}

// TestFromContext_FallsBackToGlobal is what makes it safe for
// internal/service to call logging.FromContext(ctx) unconditionally, even
// from a code path (a test, a background job) that never ran through
// middleware.RequestID.
func TestFromContext_FallsBackToGlobal(t *testing.T) {
	got := FromContext(context.Background())
	if got == nil {
		t.Fatal("FromContext() on a bare context = nil, want the global logger")
	}
}

func TestWithContext_RoundTrips(t *testing.T) {
	want := zap.NewNop().With(zap.String("request_id", "req_abc"))
	ctx := WithContext(context.Background(), want)

	got := FromContext(ctx)
	if got != want {
		t.Error("FromContext(WithContext(ctx, l)) did not return the same logger instance")
	}
}
