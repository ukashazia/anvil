package anvil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"hash"
	"io"

	"github.com/ukashazia/anvil/internal"
)

type Signer interface {
	Sign(p []byte) ([]byte, error)
	Algorithm() Algorithm
}

// concrete implementation

// hmac signing

type HmacSigner struct {
	secret internal.HmacSecret
}

func LoadHmacSecret(secret []byte) internal.HmacSecret {
	return secret
}

func GenerateHmacSecret() (internal.HmacSecret, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func NewHmacSigner(s internal.HmacSecret) *HmacSigner {
	return &HmacSigner{s}
}

func (s *HmacSigner) Algorithm() Algorithm {
	return Hmac
}

func (h *HmacSigner) Sign(d []byte) ([]byte, error) {
	mac := hmac.New(func() hash.Hash {
		return sha256.New()
	}, h.secret)
	_, err := mac.Write(d)
	if err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

// ecdsa signing

type EcdsaSigner struct {
	priv       *ecdsa.PrivateKey
	randReader io.Reader
}

func LoadEcdsaPrivateKey(key []byte) (internal.PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return priv.(*ecdsa.PrivateKey), nil
}

func GenerateEcdsaPrivateKey() (internal.PrivateKey, error) {
	randReader := rand.Reader
	priv, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func NewEcdsaSigner(key internal.PrivateKey) (*EcdsaSigner, error) {
	randReader := rand.Reader
	return &EcdsaSigner{
		priv:       key,
		randReader: randReader,
	}, nil
}

func (s *EcdsaSigner) PublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
}

func (s *EcdsaSigner) Sign(d []byte) ([]byte, error) {
	hash := sha256.Sum256(d)
	sig, err := ecdsa.SignASN1(s.randReader, s.priv, hash[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (s *EcdsaSigner) Algorithm() Algorithm {
	return Ecdsa
}
