package anvil_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/ukashazia/anvil/pkg/anvil"
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

func TestKeyStore_SetPublicKey(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("test-public-key")
	err = store.SetPublicKey("client1", key)
	if err != nil {
		t.Fatalf("SetPublicKey() error = %v", err)
	}
}

func TestKeyStore_GetPublicKey_Exists(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("test-public-key")
	store.SetPublicKey("client1", key)

	retrieved, err := store.GetPublicKey("client1")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key) {
		t.Errorf("GetPublicKey() = %v, want %v", retrieved, key)
	}
}

func TestKeyStore_GetPublicKey_NotExists(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	_, err = store.GetPublicKey("nonexistent")
	if err == nil {
		t.Fatal("GetPublicKey() expected error for nonexistent key")
	}

	if !errors.Is(err, anvil.NoPublicKeyError) {
		t.Errorf("GetPublicKey() error = %v, want NoPublicKeyError", err)
	}
}

func TestKeyStore_UpdatePublicKey(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key1 := []byte("key-version-1")
	key2 := []byte("key-version-2")

	store.SetPublicKey("client1", key1)
	store.SetPublicKey("client1", key2)

	retrieved, err := store.GetPublicKey("client1")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key2) {
		t.Errorf("GetPublicKey() = %v, want %v", retrieved, key2)
	}
}

func TestKeyStore_RemovePublicKey_Exists(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("test-public-key")
	store.SetPublicKey("client1", key)

	err = store.RemovePublicKey("client1")
	if err != nil {
		t.Fatalf("RemovePublicKey() error = %v", err)
	}

	_, err = store.GetPublicKey("client1")
	if err == nil {
		t.Fatal("GetPublicKey() should return error after removal")
	}

	if !errors.Is(err, anvil.NoPublicKeyError) {
		t.Errorf("GetPublicKey() error = %v, want NoPublicKeyError", err)
	}
}

func TestKeyStore_RemovePublicKey_NotExists(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	err = store.RemovePublicKey("nonexistent")
	if err != nil {
		t.Fatalf("RemovePublicKey() error = %v, want nil", err)
	}
}

func TestKeyStore_MultipleClients(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	clients := map[string][]byte{
		"client1": []byte("key1"),
		"client2": []byte("key2"),
		"client3": []byte("key3"),
	}

	for clientID, key := range clients {
		err := store.SetPublicKey(clientID, key)
		if err != nil {
			t.Fatalf("SetPublicKey(%s) error = %v", clientID, err)
		}
	}

	for clientID, expectedKey := range clients {
		retrieved, err := store.GetPublicKey(clientID)
		if err != nil {
			t.Fatalf("GetPublicKey(%s) error = %v", clientID, err)
		}

		if !bytes.Equal(retrieved, expectedKey) {
			t.Errorf("GetPublicKey(%s) = %v, want %v", clientID, retrieved, expectedKey)
		}
	}
}

func TestKeyStore_EmptyKey(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	emptyKey := []byte{}
	err = store.SetPublicKey("client1", emptyKey)
	if err != nil {
		t.Fatalf("SetPublicKey() error = %v", err)
	}

	retrieved, err := store.GetPublicKey("client1")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, emptyKey) {
		t.Errorf("GetPublicKey() = %v, want empty slice", retrieved)
	}
}

func TestKeyStore_NilKey(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	var nilKey []byte
	err = store.SetPublicKey("client1", nilKey)
	if err != nil {
		t.Fatalf("SetPublicKey() error = %v", err)
	}

	retrieved, err := store.GetPublicKey("client1")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if retrieved != nil {
		t.Errorf("GetPublicKey() = %v, want nil", retrieved)
	}
}

func TestKeyStore_ConcurrentWrites(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	var wg sync.WaitGroup
	clients := 100
	keysPerClient := 10

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			for j := 0; j < keysPerClient; j++ {
				key := []byte{byte(clientID), byte(j)}
				if err := store.SetPublicKey("client", key); err != nil {
					t.Errorf("SetPublicKey() error = %v", err)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestKeyStore_ConcurrentReadWrites(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	clients := 10
	opsPerClient := 100

	for i := 0; i < clients; i++ {
		clientID := string(rune('A' + i))
		key := []byte{byte(i)}
		store.SetPublicKey(clientID, key)
	}

	var wg sync.WaitGroup

	for i := 0; i < clients; i++ {
		wg.Add(3)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for j := 0; j < opsPerClient; j++ {
				key := []byte{byte(id), byte(j)}
				store.SetPublicKey(clientID, key)
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for j := 0; j < opsPerClient; j++ {
				store.GetPublicKey(clientID)
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			clientID := string(rune('A' + id))
			for j := 0; j < opsPerClient/2; j++ {
				store.RemovePublicKey(clientID)
				key := []byte{byte(id)}
				store.SetPublicKey(clientID, key)
			}
		}(i)
	}

	wg.Wait()
}

func TestKeyStore_RemoveAndReAdd(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key1 := []byte("first-key")
	key2 := []byte("second-key")

	store.SetPublicKey("client1", key1)
	store.RemovePublicKey("client1")
	store.SetPublicKey("client1", key2)

	retrieved, err := store.GetPublicKey("client1")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key2) {
		t.Errorf("GetPublicKey() = %v, want %v", retrieved, key2)
	}
}

func TestKeyStore_EmptyClientID(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key := []byte("test-key")
	err = store.SetPublicKey("", key)
	if err != nil {
		t.Fatalf("SetPublicKey() error = %v", err)
	}

	retrieved, err := store.GetPublicKey("")
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	if !bytes.Equal(retrieved, key) {
		t.Errorf("GetPublicKey() = %v, want %v", retrieved, key)
	}
}
