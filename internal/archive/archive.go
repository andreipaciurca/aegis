// Package archive extracts .zip and .tar.gz files, guarding against
// zip-slip (archive entries that try to write outside the destination
// directory via ".." path segments or absolute paths).
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extract unpacks a .zip or .tar.gz archive into dest, which must already
// exist. Returns an error for any other extension.
func Extract(path, dest string) error {
	switch {
	case strings.HasSuffix(path, ".zip"):
		return extractZip(path, dest)
	case strings.HasSuffix(path, ".tar.gz"):
		return extractTarGz(path, dest)
	default:
		return fmt.Errorf("unsupported archive type: %s", path)
	}
}

func extractZip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			_ = src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		closeSrcErr := src.Close()
		closeDstErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeSrcErr != nil {
			return closeSrcErr
		}
		if closeDstErr != nil {
			return closeDstErr
		}
	}
	return nil
}

func extractTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dest, h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(h.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(dst, tr)
			closeErr := dst.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}

func safeJoin(base, name string) (string, error) {
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	target := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return target, nil
}
