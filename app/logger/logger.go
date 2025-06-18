package logger

import (
	"cert-tracker/cfg"
	"log/slog"
	"os"
)

var Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	AddSource: cfg.LogAddSource,
	Level: cfg.LogLevel,
}))
