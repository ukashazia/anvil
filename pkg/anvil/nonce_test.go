package anvil_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ukashazia/anvil/pkg/anvil"
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
	duration := 5 * time.Second
	store := anvil.NewNonceStore(duration)

	if store == nil {
		t.Fatal("NewNonceStore() returned nil")
	}
}

func TestNonceStore_Set(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)

	err := store.Set("client1", "nonce1")
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	err = store.Set("client1", "nonce2")
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	err = store.Set("client2", "nonce1")
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
}

func TestNonceStore_Valid_NoClient(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)

	valid, err := store.Valid("nonexistent", "nonce1")
	if err == nil {
		t.Fatal("Valid() expected error for nonexistent client")
	}

	if !errors.Is(err, anvil.NoNonceError) {
		t.Errorf("Valid() error = %v, want NoNonceError", err)
	}

	if valid {
		t.Error("Valid() = true, want false")
	}
}

func TestNonceStore_Valid_FreshNonce(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	store.Set("client1", "nonce1")

	valid, err := store.Valid("client1", "nonce1")
	if err != nil {
		t.Fatalf("Valid() error = %v", err)
	}

	if !valid {
		t.Error("Valid() = false, want true for fresh nonce")
	}
}

func TestNonceStore_Valid_ExpiredNonce(t *testing.T) {
	store := anvil.NewNonceStore(50 * time.Millisecond)
	store.Set("client1", "nonce1")

	time.Sleep(100 * time.Millisecond)

	valid, err := store.Valid("client1", "nonce1")
	if err != nil {
		t.Fatalf("Valid() error = %v", err)
	}

	if valid {
		t.Error("Valid() = true, want false for expired nonce")
	}
}

func TestNonceStore_Valid_OnceOnly(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	store.Set("client1", "nonce1")

	valid, err := store.Valid("client1", "nonce1")
	if err != nil {
		t.Fatalf("Valid() first call error = %v", err)
	}
	if !valid {
		t.Fatal("Valid() first call = false, want true")
	}

	valid, err = store.Valid("client1", "nonce1")
	if err != nil {
		t.Fatalf("Valid() second call error = %v", err)
	}
	if valid {
		t.Error("Valid() second call = true, want false (nonce should be expired)")
	}
}

func TestNonceStore_Valid_MultipleNonces(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	store.Set("client1", "nonce1")
	store.Set("client1", "nonce2")
	store.Set("client1", "nonce3")

	tests := []struct {
		nonce string
		want  bool
	}{
		{"nonce1", true},
		{"nonce2", true},
		{"nonce3", true},
	}

	for _, tt := range tests {
		t.Run(tt.nonce, func(t *testing.T) {
			valid, err := store.Valid("client1", tt.nonce)
			if err != nil {
				t.Fatalf("Valid() error = %v", err)
			}
			if valid != tt.want {
				t.Errorf("Valid() = %v, want %v", valid, tt.want)
			}
		})
	}
}

func TestNonceStore_Concurrent(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	var wg sync.WaitGroup
	clients := 10
	noncesPerClient := 100

	for i := range clients {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			for range noncesPerClient {
				nonce := anvil.GetNonce()
				if err := store.Set("client", nonce); err != nil {
					t.Errorf("Set() error = %v", err)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestNonceStore_ConcurrentValidation(t *testing.T) {
	store := anvil.NewNonceStore(5 * time.Second)
	nonces := make([]string, 100)

	for i := range nonces {
		nonces[i] = anvil.GetNonce()
		store.Set("client1", nonces[i])
	}

	var wg sync.WaitGroup
	for _, nonce := range nonces {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			store.Valid("client1", n)
		}(nonce)
	}

	wg.Wait()
}
