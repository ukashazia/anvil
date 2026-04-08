package anvil_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/ukashazia/anvil"
)

func TestNewKeyStore(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	if store == nil {
		t.Fatal("NewKeyStore() returned nil")
	}
}

func TestKeyStore_SetGet_Hmac(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("hmac-key")
	if err := store.SetKey("client1", anvil.Hmac, key); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	retrieved, err := store.GetKey("client1", anvil.Hmac)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key) {
		t.Fatalf("GetKey() = %v, want %v", retrieved, key)
	}
}

func TestKeyStore_SetGet_Ecdsa(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("ecdsa-public-key")
	if err := store.SetKey("client1", anvil.Ecdsa, key); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	retrieved, err := store.GetKey("client1", anvil.Ecdsa)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key) {
		t.Fatalf("GetKey() = %v, want %v", retrieved, key)
	}
}

func TestKeyStore_GetKey_NotExists(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	_, err = store.GetKey("nonexistent", anvil.Hmac)
	if !errors.Is(err, anvil.ErrNoKey) {
		t.Fatalf("GetKey() error = %v, want %v", err, anvil.ErrNoKey)
	}
}

func TestKeyStore_UnsupportedAlgorithm(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	if err := store.SetKey("client1", anvil.Hmac, []byte("k")); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	_, err = store.GetKey("client1", anvil.Algorithm(999))
	if !errors.Is(err, anvil.ErrNoKey) {
		t.Fatalf("GetKey() error = %v, want %v", err, anvil.ErrNoKey)
	}
}

func TestKeyStore_RemoveKey(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	if err := store.SetKey("client1", anvil.Hmac, []byte("key")); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	if err := store.RemoveKey("client1", anvil.Hmac); err != nil {
		t.Fatalf("RemoveKey() error = %v", err)
	}

	_, err = store.GetKey("client1", anvil.Hmac)
	if !errors.Is(err, anvil.ErrNoKey) {
		t.Fatalf("GetKey() error = %v, want %v", err, anvil.ErrNoKey)
	}
}

func TestKeyStore_ConcurrentReadWrites(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	clients := 10
	opsPerClient := 100

	for i := range clients {
		clientID := string(rune('A' + i))
		if err := store.SetKey(clientID, anvil.Hmac, []byte{byte(i)}); err != nil {
			t.Fatalf("SetKey() error = %v", err)
		}
	}

	var wg sync.WaitGroup

	for i := range clients {
		wg.Add(3)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for j := range opsPerClient {
				_ = store.SetKey(clientID, anvil.Hmac, []byte{byte(id), byte(j)})
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for range opsPerClient {
				_, _ = store.GetKey(clientID, anvil.Hmac)
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for range opsPerClient / 2 {
				_ = store.RemoveKey(clientID, anvil.Hmac)
				_ = store.SetKey(clientID, anvil.Hmac, []byte{byte(id)})
			}
		}(i)
	}

	wg.Wait()
}
