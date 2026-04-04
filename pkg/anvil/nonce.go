package anvil

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type NonceStorer interface {
	Set(clientId string, nonce string) error
	Valid(clientId string, nonce string) (bool, error)
}

type NonceStore struct {
	duration time.Duration
	data     sync.Map
}

func GetNonce() string {
	r := make([]byte, 16)
	_, err := rand.Reader.Read(r)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(r)
}

func NewNonceStore(d time.Duration) *NonceStore {
	return &NonceStore{
		duration: d,
		data:     sync.Map{},
	}
}

type nonceValue struct {
	time    time.Time
	expired bool
}

type nonceKey struct {
	key    string
	client string
}

func (s *NonceStore) Set(c string, n string) error {
	key := nonceKey{
		key:    n,
		client: c,
	}

	_, exists := s.data.Load(key)
	if !exists {
		s.data.Store(key, nonceValue{time.Now(), false})
		return nil
	}

	return DuplicateNonce
}

func (s *NonceStore) Valid(c string, n string) (bool, error) {

	key := nonceKey{
		key:    n,
		client: c,
	}

	v, exists := s.data.Load(key)
	if !exists {
		return false, NoNonceError
	}

	value := v.(nonceValue)

	if value.expired {
		return false, nil
	}

	value.expired = true
	s.data.Store(key, value)

	if time.Since(value.time) > s.duration {
		return false, nil
	}

	return true, nil
}
