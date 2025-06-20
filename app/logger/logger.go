package logger

import (
	"cert-tracker/cfg"
	"log/slog"
	"os"
)

func New(config cfg.Params) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: config.LogAddSource,
		Level:     config.LogLevel,
	}))
}
