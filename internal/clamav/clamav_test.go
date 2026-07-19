package clamav

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanFileClean(t *testing.T) {
	client, closeServer := fakeServer(t, "stream: OK\x00")
	defer closeServer()
	path := writeTempFile(t, "hello")

	finding, clean, err := client.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !clean || finding.Signature != "" {
		t.Fatalf("unexpected result clean=%v finding=%+v", clean, finding)
	}
}

func TestScanFileFound(t *testing.T) {
	client, closeServer := fakeServer(t, "stream: Eicar-Test-Signature FOUND\x00")
	defer closeServer()
	path := writeTempFile(t, "X5O!P")

	finding, clean, err := client.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if clean || finding.Signature != "Eicar-Test-Signature" || finding.Path != path {
		t.Fatalf("unexpected result clean=%v finding=%+v", clean, finding)
	}
}

func TestScanPath(t *testing.T) {
	client, closeServer := fakeServer(t, "stream: Eicar-Test-Signature FOUND\x00")
	defer closeServer()
	dir := t.TempDir()
	writeNamedFile(t, dir, "one.txt", "one")
	writeNamedFile(t, dir, "two.txt", "two")

	report := client.ScanPath(context.Background(), dir)
	if report.Scanned != 2 || len(report.Findings) != 2 || report.Error != "" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestNewParsesAddress(t *testing.T) {
	c, err := New("tcp://127.0.0.1:3310")
	if err != nil {
		t.Fatalf("new tcp: %v", err)
	}
	if c.Network != "tcp" || c.Address != "127.0.0.1:3310" {
		t.Fatalf("unexpected tcp client: %+v", c)
	}
	c, err = New("unix:///tmp/clamd.sock")
	if err != nil {
		t.Fatalf("new unix: %v", err)
	}
	if c.Network != "unix" || c.Address != "/tmp/clamd.sock" {
		t.Fatalf("unexpected unix client: %+v", c)
	}
}

func fakeServer(t *testing.T, reply string) (Client, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeClamd(conn, reply)
		}
	}()
	return Client{Network: "tcp", Address: ln.Addr().String(), Timeout: 2 * time.Second}, func() {
		_ = ln.Close()
		<-done
	}
}

func handleFakeClamd(conn net.Conn, reply string) {
	defer conn.Close()
	command, _ := readNullTerminated(conn)
	if command == "zPING" {
		_, _ = conn.Write([]byte("PONG\x00"))
		return
	}
	if command != "zINSTREAM" {
		_, _ = conn.Write([]byte("UNKNOWN ERROR\x00"))
		return
	}
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 {
			break
		}
		if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
			return
		}
	}
	_, _ = conn.Write([]byte(reply))
}

func readNullTerminated(r io.Reader) (string, error) {
	var out []byte
	var b [1]byte
	for {
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(out), nil
		}
		out = append(out, b[0])
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	return writeNamedFile(t, dir, "sample.txt", content)
}

func writeNamedFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}
