package logging

import (
	"io"
	"log/slog"
	"testing"
)

// Критерий Ф1-1: выключенный Debug не должен стоить ничего измеримого.
// slog проверяет уровень до вычисления атрибутов, но эта защита обходится,
// если аргумент собирается выражением прямо в вызове - поэтому оба варианта
// меряются рядом, и разница между ними и есть цена неаккуратного вызова.
func BenchmarkDebugDisabled_StructuredAttrs(b *testing.B) {
	SetLevel(slog.LevelInfo)
	logger := New(io.Discard)
	err := io.EOF
	b.ReportAllocs()
	for b.Loop() {
		logger.Debug("socks: failed to authenticate", "err", err, "phase", "auth")
	}
}

func BenchmarkDebugEnabled_StructuredAttrs(b *testing.B) {
	SetLevel(slog.LevelDebug)
	defer SetLevel(slog.LevelInfo)
	logger := New(io.Discard)
	err := io.EOF
	b.ReportAllocs()
	for b.Loop() {
		logger.Debug("socks: failed to authenticate", "err", err, "phase", "auth")
	}
}

func BenchmarkInfoBaseline(b *testing.B) {
	SetLevel(slog.LevelInfo)
	logger := New(io.Discard)
	b.ReportAllocs()
	for b.Loop() {
		logger.Info("listener accepted", "transport", "obfs")
	}
}
