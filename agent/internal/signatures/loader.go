package signatures

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const maxFileBytes = 1 << 20

// Loader reads signature files and directories and keeps the last valid
// version of each file. A typo in one file therefore never removes rules that
// were already being enforced; the error is reported until it is fixed.
type Loader struct {
	paths   []string
	current atomic.Pointer[Set]

	mu    sync.Mutex
	files map[string]cachedFile
	roots map[string][]string
}

type cachedFile struct {
	digest [sha256.Size]byte
	parsed parsed
	valid  bool
	err    error
}

// ReloadResult summarizes one reload for logs and metrics.
type ReloadResult struct {
	Files   int
	Rules   int
	Changed bool
	Errors  []error
}

func NewLoader(paths []string) *Loader {
	loader := &Loader{files: make(map[string]cachedFile), roots: make(map[string][]string)}
	for _, path := range paths {
		if path = strings.TrimSpace(path); path != "" {
			loader.paths = append(loader.paths, path)
		}
	}
	loader.current.Store(&Set{})

	return loader
}

// Current returns the active rule set. It never returns nil.
func (l *Loader) Current() *Set {
	return l.current.Load()
}

// Reload rescans every configured path. Unchanged files are not re-parsed.
func (l *Loader) Reload() ReloadResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := ReloadResult{}
	files, errs := l.discover()
	result.Errors = append(result.Errors, errs...)

	seen := make(map[string]bool, len(files))
	ordered := make([]parsed, 0, len(files))
	for _, path := range files {
		seen[path] = true
		info, err := os.Stat(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", path, err))
			if cached, ok := l.files[path]; ok && cached.valid {
				ordered = append(ordered, cached.parsed)
			}
			continue
		}

		data, err := readFile(path, info)
		digest := sha256.Sum256(data)
		cached, ok := l.files[path]
		if err == nil && ok && cached.digest == digest {
			if cached.err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("%s: %w", path, cached.err))
			}
			if cached.valid {
				ordered = append(ordered, cached.parsed)
			}
			continue
		}

		result.Changed = true
		var next parsed
		if err == nil {
			next, err = Parse(data)
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("%s: %w", path, err))
			// Remember the bad version so it is not re-parsed every interval,
			// but keep enforcing the last good rules from this file.
			l.files[path] = cachedFile{digest: digest, parsed: cached.parsed, valid: cached.valid, err: err}
			if cached.valid {
				ordered = append(ordered, cached.parsed)
			}
			continue
		}

		l.files[path] = cachedFile{digest: digest, parsed: next, valid: true}
		ordered = append(ordered, next)
	}

	for path := range l.files {
		if !seen[path] {
			delete(l.files, path)
			result.Changed = true
		}
	}

	set := newSet(ordered)
	if set.Len() > maxRules*4 {
		result.Errors = append(result.Errors, fmt.Errorf("at most %d active rules are supported", maxRules*4))
		result.Rules = l.current.Load().Len()
		return result
	}
	if result.Changed {
		l.current.Store(set)
	}
	result.Files = len(ordered)
	result.Rules = l.current.Load().Len()

	return result
}

// discover expands directories to their *.json files in lexical order. A
// missing directory is not an error so a default drop-in path can be empty.
func (l *Loader) discover() ([]string, []error) {
	var files []string
	var errs []error
	for _, path := range l.paths {
		info, err := os.Stat(path)
		if err != nil {
			if previous, known := l.roots[path]; known {
				files = append(files, previous...)
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			} else if filepath.Ext(path) == ".json" {
				files = append(files, path)
			} else if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			}
			continue
		}
		if !info.IsDir() {
			l.roots[path] = []string{path}
			files = append(files, path)
			continue
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			files = append(files, l.roots[path]...)
			continue
		}
		matches := make([]string, 0, len(entries))
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				matches = append(matches, filepath.Join(path, entry.Name()))
			}
		}
		sort.Strings(matches)
		l.roots[path] = matches
		files = append(files, matches...)
	}

	return files, errs
}

func readFile(path string, info os.FileInfo) ([]byte, error) {
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxFileBytes)
	}

	return data, nil
}
