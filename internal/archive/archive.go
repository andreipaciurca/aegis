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
	"path"
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
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			link, err := safeLinkTarget(dest, target, h.Linkname)
			if err != nil {
				return err
			}
			if err := replaceWithSymlink(target, link); err != nil {
				return err
			}
		}
	}
}

// safeLinkTarget verifies that a symlink target resolves inside base. Tar
// links are relative to the link itself, unlike archive entry paths which are
// relative to the extraction root.
func safeLinkTarget(base, linkPath, linkName string) (string, error) {
	if archiveEntryIsAbsolute(linkName) {
		return "", fmt.Errorf("unsafe archive link target %q", linkName)
	}
	posix := path.Clean(strings.ReplaceAll(linkName, "\\", "/"))
	resolved := filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(posix))
	rel, err := filepath.Rel(base, resolved)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive link target %q", linkName)
	}
	return filepath.FromSlash(posix), nil
}

func replaceWithSymlink(path, link string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("cannot replace archive directory with symlink: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(link, path)
}

func safeJoin(base, name string) (string, error) {
	if archiveEntryIsAbsolute(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	// Archive entry names are POSIX-style (forward slashes) regardless of
	// the extracting host's OS, so ".." segments are resolved with the
	// path package rather than filepath — filepath.Clean/IsAbs follow
	// host conventions (e.g. a leading "/" isn't "absolute" on Windows),
	// which would let a POSIX-style traversal slip through on Windows.
	posix := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if posix == ".." || strings.HasPrefix(posix, "../") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	target := filepath.Join(base, filepath.FromSlash(posix))
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return target, nil
}

// archiveEntryIsAbsolute reports whether name looks like an absolute path
// under either POSIX or Windows conventions, independent of the host OS
// actually doing the extracting.
func archiveEntryIsAbsolute(name string) bool {
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' { // drive letter, e.g. "C:\..." or "C:/..."
		return true
	}
	return false
}
