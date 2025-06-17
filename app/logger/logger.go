package logger

import (
	"context"
	"log/slog"
	"runtime"
)

type LocationHandler struct {
	Handler       slog.Handler
	LogTraceLevel slog.Level
}

func (h *LocationHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.Handler.Enabled(ctx, level)
}

func (h *LocationHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.LogTraceLevel {
		// Skip 3 frames: Handle + log function + user code
		pc, file, line, ok := runtime.Caller(3)
		if ok {
			r.Add(
				"file", slog.StringValue(file),
				"line", slog.IntValue(line),
				"function", slog.StringValue(runtime.FuncForPC(pc).Name()),
			)
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h *LocationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LocationHandler{h.Handler.WithAttrs(attrs), h.LogTraceLevel}
}

func (h *LocationHandler) WithGroup(name string) slog.Handler {
	return &LocationHandler{h.Handler.WithGroup(name), h.LogTraceLevel}
}
