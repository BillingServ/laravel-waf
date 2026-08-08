package blocklist

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	stateVersion  = 1
	fileMode      = 0o600
	directoryMode = 0o750
)

// Record describes an IP block that was accepted by the agent.
type Record struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	ExpiresAt int64  `json:"expires_at"`
}

type diskState struct {
	Version int      `json:"version"`
	Blocks  []Record `json:"blocks"`
}

// FileStore keeps the reason and expiry for accepted block decisions. The
// firewall kernel state remains authoritative for enforcement; this file is
// the agent's explanation/audit ledger.
type FileStore struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

func NewFileStore(path string) (*FileStore, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("block state file must be an absolute path")
	}

	if err := os.MkdirAll(filepath.Dir(path), directoryMode); err != nil {
		return nil, fmt.Errorf("create block state directory: %w", err)
	}

	return &FileStore{path: path, now: time.Now}, nil
}

func (s *FileStore) RecordBlock(ip net.IP, ttlSeconds int, reason string) error {
	normalized, err := normalizeIP(ip)
	if err != nil {
		return err
	}
	if ttlSeconds < 1 {
		return fmt.Errorf("block TTL must be positive")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("block reason is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	blocks, _, err := s.load(now)
	if err != nil {
		return err
	}
	blocks[normalized] = Record{
		IP:        normalized,
		Reason:    reason,
		ExpiresAt: now.Unix() + int64(ttlSeconds),
	}

	return s.save(blocks)
}

func (s *FileStore) RemoveBlock(ip net.IP) error {
	normalized, err := normalizeIP(ip)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	blocks, exists, err := s.load(s.now())
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if _, ok := blocks[normalized]; !ok {
		return nil
	}
	delete(blocks, normalized)

	return s.save(blocks)
}

func (s *FileStore) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blocks, exists, err := s.load(s.now())
	if err != nil {
		return nil, err
	}
	if !exists {
		return []Record{}, nil
	}

	records := make([]Record, 0, len(blocks))
	for _, record := range blocks {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].IP < records[j].IP
	})

	return records, nil
}

func (s *FileStore) load(now time.Time) (map[string]Record, bool, error) {
	contents, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return map[string]Record{}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read block state: %w", err)
	}

	var state diskState
	if err := json.Unmarshal(contents, &state); err != nil {
		return nil, true, fmt.Errorf("decode block state: %w", err)
	}
	if state.Version != stateVersion {
		return nil, true, fmt.Errorf("unsupported block state version %d", state.Version)
	}

	blocks := make(map[string]Record, len(state.Blocks))
	nowUnix := now.Unix()
	for _, record := range state.Blocks {
		ip := net.ParseIP(record.IP)
		if ip == nil || record.ExpiresAt <= 0 || strings.TrimSpace(record.Reason) == "" {
			return nil, true, fmt.Errorf("invalid block state record")
		}
		normalized, err := normalizeIP(ip)
		if err != nil {
			return nil, true, err
		}
		if record.ExpiresAt <= nowUnix {
			continue
		}

		record.IP = normalized
		blocks[normalized] = record
	}

	return blocks, true, nil
}

func (s *FileStore) save(blocks map[string]Record) error {
	records := make([]Record, 0, len(blocks))
	for _, record := range blocks {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].IP < records[j].IP
	})

	contents, err := json.MarshalIndent(diskState{
		Version: stateVersion,
		Blocks:  records,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode block state: %w", err)
	}
	contents = append(contents, '\n')

	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".blocks-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary block state: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set block state permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write block state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync block state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close block state: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("replace block state: %w", err)
	}

	return nil
}

func normalizeIP(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("nil IP address")
	}

	if parsed := net.ParseIP(ip.String()); parsed != nil {
		return parsed.String(), nil
	}

	return "", fmt.Errorf("invalid IP address")
}
