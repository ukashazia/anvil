package anvil

import "sync"

type KeyStorer interface {
	SetPublicKey(clientId string, key []byte) error
	GetPublicKey(clientId string) ([]byte, error)
	RemovePublicKey(clientId string) error
}

type keyStore struct {
	data sync.Map
}

func NewKeyStore() (*keyStore, error) {
	return &keyStore{
		data: sync.Map{},
	}, nil
}

func (s *keyStore) SetPublicKey(clientId string, key []byte) error {
	s.data.Store(clientId, key)
	return nil
}

func (s *keyStore) GetPublicKey(clientId string) ([]byte, error) {
	k, present := s.data.Load(clientId)
	if !present {
		return nil, NoPublicKeyError
	}

	return k.([]byte), nil
}

func (s *keyStore) RemovePublicKey(clientId string) error {
	s.data.Delete(clientId)

	return nil
}
