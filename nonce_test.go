package anvil_test

import (
	"sync"
	"testing"
	"time"

	"github.com/ukashazia/anvil"
)

func TestGetNonce(t *testing.T) {
	nonce := anvil.GetNonce()
	if nonce == "" {
		t.Fatal("GetNonce() returned empty string")
	}

	if len(nonce) != 32 {
		t.Errorf("GetNonce() length = %d, want 32", len(nonce))
	}

	for _, c := range nonce {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GetNonce() contains invalid hex char: %c", c)
		}
	}
}

func TestGetNonceUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 1000

	for range iterations {
		nonce := anvil.GetNonce()
		if seen[nonce] {
			t.Fatalf("GetNonce() generated duplicate: %s", nonce)
		}
		seen[nonce] = true
	}
}

func TestNewNonceStore(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)

	if store == nil {
		t.Fatal("NewNonceStore() returned nil")
	}
}

func TestNonceStore_Mark(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)

	err := store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	err = store.Mark("nonce2")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
}

func TestNonceStore_Mark_SameNonceMultipleTimes(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)

	err := store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	err = store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
}

func TestNonceStore_Prune_RemovesExpiredNonces(t *testing.T) {
	store := anvil.NewNonceStore(50 * time.Millisecond)

	err := store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	err = store.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	err = store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() after Prune() error = %v", err)
	}
}

func TestNonceStore_Prune_LeavesFreshNonces(t *testing.T) {
	store := anvil.NewNonceStore(50 * time.Millisecond)

	err := store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	err = store.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	err = store.Mark("nonce1")
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
}

func TestNonceStore_ConcurrentMark(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	var wg sync.WaitGroup
	workers := 10
	noncesPerWorker := 100

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range noncesPerWorker {
				nonce := anvil.GetNonce()
				if err := store.Mark(nonce); err != nil {
					t.Errorf("Mark() error = %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

func TestNonceStore_ConcurrentPrune(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	nonces := make([]string, 100)

	for i := range nonces {
		nonces[i] = anvil.GetNonce()
		if err := store.Mark(nonces[i]); err != nil {
			t.Fatalf("Mark() error = %v", err)
		}
	}

	var wg sync.WaitGroup
	for range nonces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.Prune(); err != nil {
				t.Errorf("Prune() error = %v", err)
			}
		}()
	}

	wg.Wait()
}
