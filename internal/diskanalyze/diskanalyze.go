// Package diskanalyze provides a bounded disk usage summary for security
// triage: unusually large files, exposed archives and top-level space users.
package diskanalyze

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultLargeFileSize = 500 << 20 // 500 MiB
	MaxLargeFiles        = 20
)

type Entry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
}

type LargeFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Reason string `json:"reason,omitempty"`
}

type Report struct {
	Path       string      `json:"path"`
	Entries    []Entry     `json:"entries"`
	LargeFiles []LargeFile `json:"large_files,omitempty"`
	TotalSize  int64       `json:"total_size"`
	TotalFiles int64       `json:"total_files"`
	Skipped    int64       `json:"skipped"`
}

func Analyze(root string) (Report, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Report{}, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return Report{}, err
	}
	if !info.IsDir() {
		return Report{}, &fs.PathError{Op: "analyze", Path: root, Err: fs.ErrInvalid}
	}

	report := Report{Path: root}
	rootPrefix := root + string(filepath.Separator)
	children, _ := os.ReadDir(root)
	sizeByChild := make(map[string]int64, len(children))
	for _, child := range children {
		sizeByChild[filepath.Join(root, child.Name())] = 0
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			report.Skipped++
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				report.Skipped++
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			report.Skipped++
			return nil
		}
		size := info.Size()
		report.TotalFiles++
		report.TotalSize += size
		if top := topChild(root, rootPrefix, path); top != "" {
			sizeByChild[top] += size
		}
		if size >= DefaultLargeFileSize {
			report.LargeFiles = append(report.LargeFiles, LargeFile{
				Name:   d.Name(),
				Path:   path,
				Size:   size,
				Reason: largeFileReason(d.Name()),
			})
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}

	for _, child := range children {
		path := filepath.Join(root, child.Name())
		report.Entries = append(report.Entries, Entry{
			Name:  child.Name(),
			Path:  path,
			Size:  sizeByChild[path],
			IsDir: child.IsDir(),
		})
	}
	sort.SliceStable(report.Entries, func(i, j int) bool {
		return report.Entries[i].Size > report.Entries[j].Size
	})
	sort.SliceStable(report.LargeFiles, func(i, j int) bool {
		return report.LargeFiles[i].Size > report.LargeFiles[j].Size
	})
	if len(report.LargeFiles) > MaxLargeFiles {
		report.LargeFiles = report.LargeFiles[:MaxLargeFiles]
	}
	return report, nil
}

func topChild(root, rootPrefix, path string) string {
	if !strings.HasPrefix(path, rootPrefix) {
		return ""
	}
	rel := path[len(rootPrefix):]
	first := strings.Split(rel, string(filepath.Separator))[0]
	return filepath.Join(root, first)
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".Trash", "Caches", "cache", ".cache",
		"DerivedData", ".npm", ".cargo", "go", "Xcode", ".docker", "Photos Library.photoslibrary":
		return true
	}
	return false
}

func largeFileReason(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz":
		return "large archive"
	case ".dmg", ".iso", ".pkg", ".msi":
		return "installer or disk image"
	case ".sql", ".db", ".sqlite", ".sqlite3", ".bak":
		return "large data store or backup"
	case ".pem", ".key", ".p12", ".pfx":
		return "key material"
	}
	return "large file"
}
