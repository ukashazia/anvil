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

type nonceValue struct {
	setAt time.Time
}

type nonceKey struct {
	key string
}

func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		ttl:  ttl,
		data: sync.Map{},
	}
}

func (s *NonceStore) Mark(n string) error {
	key := nonceKey{
		key: n,
	}

	_, exists := s.data.Load(key)
	if !exists {
		s.data.Store(key, nonceValue{
			setAt: time.Now(),
		})
		return nil
	}

	return ErrNonceExists
}

func (s *NonceStore) Prune() error {
	s.data.Range(func(key, value any) bool {
		nonceKey := key.(nonceKey)
		nonceValue := value.(nonceValue)
		if time.Since(nonceValue.setAt) > s.ttl {
			s.data.Delete(nonceKey)
		}

		return true
	})

	return nil
}

func GetNonce() (string, error) {
	r := make([]byte, 16)
	_, err := rand.Reader.Read(r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(r), nil
}
