package anvil

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type NonceStorer interface {
	Mark(nonce string) error
	Prune() error
}

type NonceStore struct {
	ttl  time.Duration
	data sync.Map
}

type nonceValue struct{}

type nonceKey struct {
	key   string
	setAt time.Time
}

func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		ttl:  ttl,
		data: sync.Map{},
	}
}

func (s *NonceStore) Mark(n string) error {
	key := nonceKey{
		key:   n,
		setAt: time.Now(),
	}

	_, exists := s.data.Load(key)
	if !exists {
		s.data.Store(key, nonceValue{})
		return nil
	}

	return NonceExists
}

func (s *NonceStore) Prune() error {
	s.data.Range(func(key, value any) bool {
		nonce := key.(nonceKey)
		if time.Since(nonce.setAt) > s.ttl {
			s.data.Delete(nonce)
		}

		return true
	})

	return nil
}

func GetNonce() string {
	r := make([]byte, 16)
	_, err := rand.Reader.Read(r)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(r)
}
