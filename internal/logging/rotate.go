package logging

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FileOptions configure a RotatingFile.
type FileOptions struct {
	// Path is the live file.
	Path string
	// MaxSize rotates the file before a write would take it past this many
	// bytes. Zero never rotates by size.
	MaxSize int64
	// Keep is how many rotated files are kept. Zero keeps them all.
	Keep int
	// MaxAge removes rotated files older than this. Zero keeps them by count
	// only.
	MaxAge time.Duration
	// ArchiveDir is where rotated files go; empty is next to Path.
	ArchiveDir string
	// Compress gzips a rotated file, in the background.
	Compress bool
	// RotateOnOpen moves a non-empty file left by the previous run to the
	// archive before the first write, so that every run starts a file of its
	// own.
	RotateOnOpen bool
	// Mode is the permission of new files; zero is 0600.
	Mode os.FileMode
}

// RotatingFile is an append-only file that moves itself aside by size, keeps a
// bounded archive of what it moved and needs nothing from outside to do it:
// the same code runs in a container, on a router and on Windows, where a file
// a process holds open cannot be renamed by anyone else.
type RotatingFile struct {
	opts FileOptions

	mu   sync.Mutex
	f    *os.File
	size int64

	// background is the gzip of rotated files still running.
	background sync.WaitGroup
}

// OpenRotating opens the file, creating its directory, and applies RotateOnOpen.
func OpenRotating(opts FileOptions) (*RotatingFile, error) {
	if opts.Path == "" {
		return nil, errors.New("logging: no file path")
	}
	if opts.Mode == 0 {
		opts.Mode = 0o600
	}
	r := &RotatingFile{opts: opts}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}
	info, err := os.Lstat(opts.Path)
	if err == nil && !info.Mode().IsRegular() {
		// Rotation renames the path: a directory or a device named by mistake
		// would be moved into the archive, and a link would have the journal
		// appended to a file someone else chose.
		return nil, fmt.Errorf("logging: %s is not a regular file", opts.Path)
	}
	if opts.RotateOnOpen && err == nil && info.Size() > 0 {
		if err := r.archive(info.ModTime()); err != nil {
			return nil, err
		}
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	// The mode applies to a file this call creates; an existing file keeps the
	// mode its owner gave it.
	f, err := os.OpenFile(r.opts.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|noFollow, r.opts.Mode)
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("logging: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("logging: %s is not a regular file", r.opts.Path)
	}
	r.f, r.size = f, info.Size()
	return nil
}

// Write appends p, rotating first if p would take the file past MaxSize. A
// write that fails leaves the file usable for the next one.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.opts.MaxSize > 0 && r.size > 0 && r.size+int64(len(p)) > r.opts.MaxSize {
		if err := r.rotateLocked(); err != nil && r.f == nil {
			return 0, err
		}
	}
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Rotate moves the live file to the archive now.
func (r *RotatingFile) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateLocked()
}

func (r *RotatingFile) rotateLocked() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	if r.size > 0 {
		if err := r.archive(time.Now()); err != nil {
			return err
		}
	}
	return r.open()
}

// Reopen closes the file and opens the same path again, for a rotation done
// from outside (logrotate with create).
func (r *RotatingFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	return r.open()
}

// Size is the size of the live file.
func (r *RotatingFile) Size() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Close closes the live file and waits for background compression.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	var err error
	if r.f != nil {
		err = r.f.Close()
		r.f = nil
	}
	r.mu.Unlock()
	r.background.Wait()
	return err
}

// archiveStamp is the time in an archived name: no colon, which Windows does
// not allow.
const archiveStamp = "20060102T150405.000Z"

// archiveName is where a file rotated at t goes: <stem>-<time>[-<n>]<ext>,
// with n counting files rotated within the same millisecond.
func (r *RotatingFile) archiveName(t time.Time) string {
	dir := r.archiveDir()
	stem, ext := r.stemExt()
	stamp := t.UTC().Format(archiveStamp)
	at, _ := time.Parse(archiveStamp, stamp)
	// The count goes past every file of this millisecond, not into a gap
	// pruning left: a reused lower count would sort as the oldest.
	next := 0
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if a, ok := parseArchived(e.Name(), stem, ext); ok && a.at.Equal(at) {
				next = max(next, a.n+1)
			}
		}
	}
	taken := func(name string) bool { return exists(name) || exists(name+".gz") }
	name := filepath.Join(dir, stem+"-"+stamp+ext)
	if next == 0 && !taken(name) {
		return name
	}
	for n := max(next, 1); ; n++ {
		name = filepath.Join(dir, fmt.Sprintf("%s-%s-%d%s", stem, stamp, n, ext))
		if !taken(name) {
			return name
		}
	}
}

func (r *RotatingFile) stemExt() (stem, ext string) {
	base := filepath.Base(r.opts.Path)
	ext = filepath.Ext(base)
	return strings.TrimSuffix(base, ext), ext
}

// archivedFile is one file archiveName produced, with what orders it.
type archivedFile struct {
	name string
	at   time.Time
	n    int
}

// parseArchived reads a name archiveName produced; any other name is not
// this file's archive and is left alone.
func parseArchived(name, stem, ext string) (archivedFile, bool) {
	rest, ok := strings.CutPrefix(name, stem+"-")
	if !ok {
		return archivedFile{}, false
	}
	rest = strings.TrimSuffix(rest, ".gz")
	if rest, ok = strings.CutSuffix(rest, ext); !ok || len(rest) < len(archiveStamp) {
		return archivedFile{}, false
	}
	at, err := time.Parse(archiveStamp, rest[:len(archiveStamp)])
	if err != nil {
		return archivedFile{}, false
	}
	a := archivedFile{name: name, at: at}
	if suffix := rest[len(archiveStamp):]; suffix != "" {
		digits, ok := strings.CutPrefix(suffix, "-")
		if !ok || digits == "" || digits[0] == '0' {
			return archivedFile{}, false
		}
		for _, c := range digits {
			if c < '0' || c > '9' {
				return archivedFile{}, false
			}
		}
		if a.n, err = strconv.Atoi(digits); err != nil {
			return archivedFile{}, false
		}
	}
	return a, true
}

func (r *RotatingFile) archiveDir() string {
	if r.opts.ArchiveDir != "" {
		return r.opts.ArchiveDir
	}
	return filepath.Dir(r.opts.Path)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// archive moves the live file aside and prunes the archive. Compression, when
// asked for, runs in the background and prunes after itself.
func (r *RotatingFile) archive(t time.Time) error {
	if err := os.MkdirAll(r.archiveDir(), 0o700); err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	name := r.archiveName(t)
	if err := os.Rename(r.opts.Path, name); err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	if !r.opts.Compress {
		r.prune()
		return nil
	}
	r.background.Add(1)
	go func() {
		defer r.background.Done()
		if err := gzipFile(name, r.opts.Mode); err == nil {
			_ = os.Remove(name)
		}
		r.prune()
	}()
	return nil
}

func gzipFile(src string, mode os.FileMode) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp := src + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	zw := gzip.NewWriter(out)
	if _, err = io.Copy(zw, in); err != nil {
		return err
	}
	if err = zw.Close(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, src+".gz")
}

// prune removes rotated files beyond Keep and older than MaxAge. Only names
// archiveName produces are considered, newest first by their time and count.
func (r *RotatingFile) prune() {
	if r.opts.Keep <= 0 && r.opts.MaxAge <= 0 {
		return
	}
	dir := r.archiveDir()
	stem, ext := r.stemExt()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// A file being compressed exists under both names for a moment; it is one
	// rotation, named here without .gz.
	var files []archivedFile
	seen := make(map[string]bool)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		a, ok := parseArchived(e.Name(), stem, ext)
		if !ok {
			continue
		}
		a.name = strings.TrimSuffix(a.name, ".gz")
		if !seen[a.name] {
			seen[a.name] = true
			files = append(files, a)
		}
	}
	sort.Slice(files, func(i, k int) bool {
		if !files[i].at.Equal(files[k].at) {
			return files[i].at.After(files[k].at)
		}
		return files[i].n > files[k].n
	})
	now := time.Now()
	for i, a := range files {
		path := filepath.Join(dir, a.name)
		old := false
		if r.opts.MaxAge > 0 {
			for _, p := range []string{path, path + ".gz"} {
				if info, err := os.Lstat(p); err == nil && now.Sub(info.ModTime()) > r.opts.MaxAge {
					old = true
				}
			}
		}
		if (r.opts.Keep > 0 && i >= r.opts.Keep) || old {
			_ = os.Remove(path)
			_ = os.Remove(path + ".gz")
		}
	}
}
