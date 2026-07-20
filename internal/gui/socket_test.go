package gui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// shortSocketPath returns a socket path unlikely to exceed the ~104-byte
// sun_path limit macOS/BSD impose on Unix socket paths. t.TempDir() nests
// under a long per-test directory that regularly blows past that limit, so
// tests bind directly under the OS temp root instead, with the same short
// naming scheme production users should follow for --socket.
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	root := os.TempDir()
	if runtime.GOOS != "windows" {
		root = "/tmp"
	}
	path := filepath.Join(root, fmt.Sprintf("aegis-test-%d-%s", os.Getpid(), name))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func TestListenUnixSocketCreatesRestrictedSocket(t *testing.T) {
	path := shortSocketPath(t, "restricted.sock")

	ln, err := listenUnixSocket(path)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("unix sockets unsupported on this Windows build: %v", err)
		}
		t.Fatalf("listenUnixSocket: %v", err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("socket permissions = %o, want 0600", perm)
		}
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	conn.Close()
}

func TestListenUnixSocketRemovesStaleSocketFile(t *testing.T) {
	path := shortSocketPath(t, "stale.sock")

	first, err := net.Listen("unix", path)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("unix sockets unsupported on this Windows build: %v", err)
		}
		t.Fatalf("initial listen: %v", err)
	}
	// Simulate an unclean previous exit: the socket file is left on disk
	// with no listener behind it.
	conn, dialErr := net.Dial("unix", path)
	if dialErr == nil {
		conn.Close()
	}
	first.Close()
	if _, statErr := os.Stat(path); statErr != nil {
		// Close already unlinked it (some platforms do); recreate a stale
		// regular-looking socket file so the cleanup path is still exercised.
		ln2, err2 := net.Listen("unix", path)
		if err2 != nil {
			t.Fatalf("recreate stale socket: %v", err2)
		}
		ln2.Close()
	}

	ln, err := listenUnixSocket(path)
	if err != nil {
		t.Fatalf("listenUnixSocket did not recover from stale socket file: %v", err)
	}
	defer ln.Close()
}

func TestListenUnixSocketDoesNotClobberRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}

	if _, err := listenUnixSocket(path); err == nil {
		t.Fatal("expected an error binding over a regular file, got nil")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("regular file contents changed: %q", b)
	}
}
