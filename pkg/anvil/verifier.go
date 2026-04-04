package anvil

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"hash"
)

type Verifier interface {
	Verify(msg []byte, sig []byte) (bool, error)
	Algorithm()
}

// concrete implementation

// hmac verification
type HmacVerifier struct {
	secret hmacSecret
}

func (v *HmacVerifier) Verify(msg []byte, sig []byte) (bool, error) {
	mac := hmac.New(func() hash.Hash {
		return sha256.New()
	}, v.secret)

	_, err := mac.Write(msg)
	if err != nil {
		return false, err
	}

	expectedSignature := mac.Sum(nil)

	return hmac.Equal(expectedSignature, sig), nil
}

func (s *HmacVerifier) Algorithm() Algorithm {
	return Hmac
}

// ecdsa verification

type EcdsaVerifier struct {
	pub *ecdsa.PublicKey
}

type PublicKey *ecdsa.PublicKey

func LoadEcdsaPublicKey(key []byte) (PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	pub := parsed.(*ecdsa.PublicKey)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func NewEcdsaVerifier(pkey PublicKey) (*EcdsaVerifier, error) {
	return &EcdsaVerifier{
		pub: pkey,
	}, nil
}

func (v *EcdsaVerifier) Verify(msg []byte, sig []byte) (bool, error) {
	return ecdsa.VerifyASN1(v.pub, msg, sig), nil
}

func (s *EcdsaVerifier) Algorithm() Algorithm {
	return Ecdsa
}
