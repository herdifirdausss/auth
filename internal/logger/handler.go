package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/herdifirdausss/auth/internal/middleware"
	"go.opentelemetry.io/otel/trace"
)

type ContextHandler struct {
	handler slog.Handler
}

func NewContextHandler(h slog.Handler) *ContextHandler {
	return &ContextHandler{handler: h}
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if requestID := middleware.GetRequestID(ctx); requestID != "" {
		r.AddAttrs(slog.String("request_id", requestID))
	}

	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		r.AddAttrs(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)
	}

	if authCtx, err := middleware.GetAuthContext(ctx); err == nil && authCtx != nil {
		if authCtx.UserID != "" {
			r.AddAttrs(slog.String("user_id", authCtx.UserID))
		}
	}

	return h.handler.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{handler: h.handler.WithGroup(name)}
}

func NewLogger(env string) *slog.Logger {
	var handler slog.Handler
	if env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, nil)
	} else {
		handler = slog.NewTextHandler(os.Stdout, nil)
	}
	return slog.New(NewContextHandler(handler))
}

func FromContext(ctx context.Context) *slog.Logger {
	return slog.Default()
}
