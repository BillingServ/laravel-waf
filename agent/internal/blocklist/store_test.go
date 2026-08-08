package blocklist

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreRecordsReasonAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocks.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }
	if err := store.RecordBlock(net.ParseIP("203.0.113.10"), 900, "manual_review"); err != nil {
		t.Fatalf("record block: %v", err)
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("list blocks: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one block, got %#v", records)
	}
	if records[0].IP != "203.0.113.10" || records[0].Reason != "manual_review" || records[0].ExpiresAt != now.Unix()+900 {
		t.Fatalf("unexpected block record: %#v", records[0])
	}
}

func TestFileStoreUpdatesAndRemovesBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocks.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	if err := store.RecordBlock(net.ParseIP("2001:db8::10"), 60, "first"); err != nil {
		t.Fatalf("record initial block: %v", err)
	}
	if err := store.RecordBlock(net.ParseIP("2001:0db8:0:0:0:0:0:10"), 120, "second"); err != nil {
		t.Fatalf("update block: %v", err)
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("list updated blocks: %v", err)
	}
	if len(records) != 1 || records[0].Reason != "second" {
		t.Fatalf("expected updated block record, got %#v", records)
	}

	if err := store.RemoveBlock(net.ParseIP("2001:db8::10")); err != nil {
		t.Fatalf("remove block: %v", err)
	}
	records, err = store.List()
	if err != nil {
		t.Fatalf("list after removal: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no block records, got %#v", records)
	}
}

func TestFileStoreDropsExpiredBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocks.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }
	if err := store.RecordBlock(net.ParseIP("203.0.113.10"), 1, "temporary"); err != nil {
		t.Fatalf("record block: %v", err)
	}

	store.now = func() time.Time { return now.Add(2 * time.Second) }
	records, err := store.List()
	if err != nil {
		t.Fatalf("list expired blocks: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected expired block to be omitted, got %#v", records)
	}
}
