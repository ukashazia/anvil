package anvil

import "sync"

type KeyStorer interface {
	SetKey(clientID string, algorithm Algorithm, key []byte) error
	GetKey(clientID string, algorithm Algorithm) ([]byte, error)
	RemoveKey(clientID string, algorithm Algorithm) error
}

type keyStore struct {
	data sync.Map
}

func NewKeyStore() (*keyStore, error) {
	return &keyStore{
		data: sync.Map{},
	}, nil
}

type storeKey struct {
	id        string
	algorithm Algorithm
}

type storeValue struct {
	sharedSecret []byte
	publicKey    []byte
}

func (s *keyStore) SetKey(clientID string, algorithm Algorithm, key []byte) error {
	k := storeKey{
		id:        clientID,
		algorithm: algorithm,
	}

	v := storeValue{}
	switch algorithm {
	case Hmac:
		v.sharedSecret = key
	case Ecdsa:
		v.publicKey = key
	default:
		return AlgorithmNotSupported
	}

	s.data.Store(k, v)
	return nil
}

func (s *keyStore) GetKey(clientID string, algorithm Algorithm) ([]byte, error) {
	k := storeKey{
		id:        clientID,
		algorithm: algorithm,
	}

	v, present := s.data.Load(k)
	if !present {
		return nil, NoKeyError
	}

	switch algorithm {
	case Hmac:
		return v.(storeValue).sharedSecret, nil
	case Ecdsa:
		return v.(storeValue).publicKey, nil
	default:
		return nil, AlgorithmNotSupported
	}
}

func (s *keyStore) RemoveKey(clientID string, algorithm Algorithm) error {
	k := storeKey{
		id:        clientID,
		algorithm: algorithm,
	}

	s.data.Delete(k)
	return nil
}
