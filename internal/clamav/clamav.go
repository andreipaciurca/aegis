// Package clamav talks to a user-supplied ClamAV daemon.
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultAddress = "tcp://127.0.0.1:3310"
	MaxFileSize    = 200 << 20
	chunkSize      = 32 << 10
)

type Client struct {
	Network string
	Address string
	Timeout time.Duration
}

type Report struct {
	Root     string    `json:"root"`
	Scanned  int64     `json:"scanned"`
	Skipped  int64     `json:"skipped"`
	Findings []Finding `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

type Finding struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
	Raw       string `json:"raw"`
}

func New(address string) (Client, error) {
	if strings.TrimSpace(address) == "" {
		address = DefaultAddress
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme == "" {
		return Client{}, fmt.Errorf("clamav address must look like tcp://127.0.0.1:3310 or unix:///path/clamd.sock")
	}
	c := Client{Network: u.Scheme, Timeout: 30 * time.Second}
	switch u.Scheme {
	case "tcp":
		c.Address = u.Host
	case "unix":
		c.Address = u.Path
	default:
		return Client{}, fmt.Errorf("unsupported clamd network %q", u.Scheme)
	}
	if c.Address == "" {
		return Client{}, fmt.Errorf("clamav address is empty")
	}
	return c, nil
}

func (c Client) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return err
	}
	reply, err := readReply(conn)
	if err != nil {
		return err
	}
	if strings.TrimSpace(reply) != "PONG" {
		return fmt.Errorf("unexpected clamd ping reply: %q", reply)
	}
	return nil
}

func (c Client) ScanPath(ctx context.Context, root string) Report {
	report := Report{Root: root}
	if resolved, err := resolveRoot(root); err == nil {
		root = resolved
		report.Root = resolved
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			report.Skipped++
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > MaxFileSize {
			report.Skipped++
			return nil
		}
		finding, clean, err := c.ScanFile(ctx, path)
		if err != nil {
			report.Skipped++
			if report.Error == "" {
				report.Error = err.Error()
			}
			return nil
		}
		report.Scanned++
		if !clean {
			report.Findings = append(report.Findings, finding)
		}
		return nil
	})
	if err != nil && report.Error == "" {
		report.Error = err.Error()
	}
	return report
}

func (c Client) ScanFile(ctx context.Context, path string) (Finding, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return Finding{}, false, err
	}
	defer f.Close()

	conn, err := c.dial(ctx)
	if err != nil {
		return Finding{}, false, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return Finding{}, false, err
	}
	buf := make([]byte, chunkSize)
	var lenBuf [4]byte
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
			if _, err := conn.Write(lenBuf[:]); err != nil {
				return Finding{}, false, err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return Finding{}, false, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return Finding{}, false, readErr
		}
	}
	binary.BigEndian.PutUint32(lenBuf[:], 0)
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return Finding{}, false, err
	}
	reply, err := readReply(conn)
	if err != nil {
		return Finding{}, false, err
	}
	return parseScanReply(path, reply)
}

func (c Client) dial(ctx context.Context) (net.Conn, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, c.Network, c.Address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func readReply(r io.Reader) (string, error) {
	reply, err := bufio.NewReader(r).ReadString(0)
	if errors.Is(err, io.EOF) && reply != "" {
		err = nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(reply, "\x00\r\n"), nil
}

func parseScanReply(path, reply string) (Finding, bool, error) {
	raw := strings.TrimSpace(reply)
	if strings.HasSuffix(raw, " OK") || raw == "OK" {
		return Finding{}, true, nil
	}
	if strings.Contains(raw, " FOUND") {
		sig := raw
		if i := strings.Index(sig, ":"); i >= 0 {
			sig = strings.TrimSpace(sig[i+1:])
		}
		sig = strings.TrimSuffix(sig, " FOUND")
		return Finding{Path: path, Signature: strings.TrimSpace(sig), Raw: raw}, false, nil
	}
	if strings.Contains(raw, " ERROR") {
		return Finding{}, false, fmt.Errorf("clamd: %s", raw)
	}
	return Finding{}, false, fmt.Errorf("unrecognized clamd reply: %q", raw)
}

func resolveRoot(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return root, err
	}
	return filepath.EvalSymlinks(root)
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".Trash", "Caches", "cache", ".cache",
		"DerivedData", ".npm", ".cargo", "go", "Xcode", ".docker", "Photos Library.photoslibrary":
		return true
	}
	return false
}
