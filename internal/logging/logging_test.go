package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{" debug ", slog.LevelDebug, false},
		{"Debug", slog.LevelDebug, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"verbose", slog.LevelInfo, true},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("ParseLevel(%q): err=%v, wantErr=%v", c.in, err, c.wantErr)
		}
		if got != c.want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Критерий Ф1-1: уровень меняется на уже созданном логгере, без пересоздания
// обработчика - то есть на работающем процессе, без рестарта.
func TestLevelChangesOnLiveLogger(t *testing.T) {
	defer SetLevel(slog.LevelInfo)

	var buf bytes.Buffer
	logger := New(&buf)

	SetLevel(slog.LevelInfo)
	logger.Debug("diagnostics")
	if buf.Len() != 0 {
		t.Fatalf("на уровне info запись Debug попала в вывод: %s", buf.String())
	}

	SetLevel(slog.LevelDebug)
	logger.Debug("diagnostics")
	if buf.Len() == 0 {
		t.Fatal("после переключения на debug запись Debug не появилась")
	}

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("вывод не JSON: %v (%s)", err, buf.String())
	}
	if rec["msg"] != "diagnostics" || rec["level"] != "DEBUG" {
		t.Fatalf("неожиданная запись: %v", rec)
	}

	buf.Reset()
	SetLevel(slog.LevelError)
	logger.Warn("noise")
	if buf.Len() != 0 {
		t.Fatalf("на уровне error запись Warn попала в вывод: %s", buf.String())
	}
}

func TestSetLevelFromEnv(t *testing.T) {
	defer SetLevel(slog.LevelInfo)

	t.Setenv(EnvVar, "debug")
	got, err := SetLevelFromEnv()
	if err != nil || got != slog.LevelDebug {
		t.Fatalf("SetLevelFromEnv() = %v, %v; want debug, nil", got, err)
	}

	// Непонятое значение не должно тушить уже включенную диагностику.
	t.Setenv(EnvVar, "louder")
	got, err = SetLevelFromEnv()
	if err == nil {
		t.Fatal("ожидалась ошибка на неизвестном уровне")
	}
	if got != slog.LevelDebug || Level() != slog.LevelDebug {
		t.Fatalf("после ошибки уровень изменился: %v", Level())
	}
}

func TestSetupInstallsDefault(t *testing.T) {
	prev := slog.Default()
	defer func() { slog.SetDefault(prev); SetLevel(slog.LevelInfo) }()

	t.Setenv(EnvVar, "warn")
	var buf bytes.Buffer
	if _, err := Setup(&buf); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if Level() != slog.LevelWarn {
		t.Fatalf("уровень = %v, want warn", Level())
	}
	slog.Info("hidden")
	slog.Warn("shown")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") {
		t.Fatalf("уровень не применился к логгеру по умолчанию: %s", out)
	}
}

// Переключение уровня идет из обработчика сигнала, параллельно с записью
// из горутин соединений: гонки здесь не должно быть по построению.
func TestConcurrentLevelSwitch(t *testing.T) {
	defer SetLevel(slog.LevelInfo)
	logger := New(os.Stderr)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				logger.Debug("probe", "j", j)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			if j%2 == 0 {
				SetLevel(slog.LevelError)
			} else {
				SetLevel(slog.LevelInfo)
			}
		}
	}()
	wg.Wait()
}

func TestSetLevelFromFile(t *testing.T) {
	defer SetLevel(slog.LevelInfo)

	dir := t.TempDir()
	path := dir + "/level"
	if err := os.WriteFile(path, []byte("debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Файл важнее переменной: окружение работающего процесса не изменить,
	// а файл - можно, и именно он делает SIGHUP осмысленным.
	t.Setenv(EnvVar, "error")
	t.Setenv(FileEnvVar, path)

	got, err := SetLevelFromEnv()
	if err != nil || got != slog.LevelDebug {
		t.Fatalf("SetLevelFromEnv() = %v, %v; want debug, nil", got, err)
	}

	if err := os.WriteFile(path, []byte("warn"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = SetLevelFromEnv()
	if err != nil || got != slog.LevelWarn {
		t.Fatalf("после перезаписи файла: %v, %v; want warn, nil", got, err)
	}

	// Нечитаемый файл не должен менять уровень: во время инцидента
	// это означало бы молча выключить диагностику.
	t.Setenv(FileEnvVar, dir+"/missing")
	got, err = SetLevelFromEnv()
	if err == nil {
		t.Fatal("ожидалась ошибка на отсутствующем файле")
	}
	if got != slog.LevelWarn || Level() != slog.LevelWarn {
		t.Fatalf("уровень изменился после ошибки чтения: %v", Level())
	}

	// Бесконечный источник не должен останавливать обработчик сигнала:
	// чтение ограничено, уровень остается прежним.
	if _, err := os.Stat("/dev/zero"); err == nil {
		t.Setenv(FileEnvVar, "/dev/zero")
		if _, err := SetLevelFromEnv(); err == nil {
			t.Fatal("ожидалась ошибка на /dev/zero")
		}
		if Level() != slog.LevelWarn {
			t.Fatalf("уровень изменился после /dev/zero: %v", Level())
		}
	}
}

func TestToggleDebug(t *testing.T) {
	defer SetLevel(slog.LevelInfo)

	SetLevel(slog.LevelInfo)
	if got := ToggleDebug(); got != slog.LevelDebug {
		t.Fatalf("ToggleDebug() = %v, want debug", got)
	}
	if got := ToggleDebug(); got != slog.LevelInfo {
		t.Fatalf("ToggleDebug() = %v, want info", got)
	}
	// Из warn переключатель тоже ведет в debug: смысл сигнала - включить
	// диагностику, а не вернуться к предыдущему уровню.
	SetLevel(slog.LevelWarn)
	if got := ToggleDebug(); got != slog.LevelDebug {
		t.Fatalf("ToggleDebug() из warn = %v, want debug", got)
	}
}
