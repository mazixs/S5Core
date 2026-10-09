//go:build unix

package configfile

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFIFOWithoutWriterIsRefusedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Read(path, 4096); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as configuration")
		}
	case <-time.After(time.Second):
		// Unblock an erroneously blocking reader before ending the test.
		if f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatal("configuration reader blocked on FIFO without writer")
	}
}
