package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
)

func TestContextHandler(t *testing.T) {
	t.Run("injects request_id", func(t *testing.T) {
		var buf bytes.Buffer
		h := NewContextHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h)

		req := httptest.NewRequest("GET", "/", nil)
		handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.InfoContext(r.Context(), "test message")
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		var data map[string]interface{}
		err := json.Unmarshal(buf.Bytes(), &data)
		assert.NoError(t, err)
		assert.NotEmpty(t, data["request_id"])
	})

	t.Run("injects user_id", func(t *testing.T) {
		var buf bytes.Buffer
		h := NewContextHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h)

		ctx := middleware.SetAuthContext(context.Background(), &middleware.AuthContext{
			UserID: "test-user-id",
		})

		logger.InfoContext(ctx, "test message")

		var data map[string]interface{}
		err := json.Unmarshal(buf.Bytes(), &data)
		assert.NoError(t, err)
		assert.Equal(t, "test-user-id", data["user_id"])
	})

	t.Run("injects trace_id and span_id", func(t *testing.T) {
		var buf bytes.Buffer
		h := NewContextHandler(slog.NewJSONHandler(&buf, nil))
		logger := slog.New(h)

		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
			SpanID:  trace.SpanID{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
		})
		ctx := trace.ContextWithSpanContext(context.Background(), sc)

		logger.InfoContext(ctx, "test message")

		var data map[string]interface{}
		err := json.Unmarshal(buf.Bytes(), &data)
		assert.NoError(t, err)
		assert.Equal(t, "01020304050607080910111213141516", data["trace_id"])
		assert.Equal(t, "0102030405060708", data["span_id"])
	})
}

func TestNewLogger(t *testing.T) {
	logger := NewLogger("development")
	assert.NotNil(t, logger)
}

func TestFromContext(t *testing.T) {
	ctx := context.Background()
	logger := FromContext(ctx)
	assert.NotNil(t, logger)
}
