package anvil_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/ukashazia/anvil/pkg/anvil"
)

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		alg  anvil.Algorithm
		want string
	}{
		{anvil.Hmac, "hmac"},
		{anvil.Ecdsa, "ecdsa"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.want {
				t.Errorf("Algorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateHmacSecret(t *testing.T) {
	secret, err := anvil.GenerateHmacSecret()
	if err != nil {
		t.Fatalf("GenerateHmacSecret() error = %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("GenerateHmacSecret() length = %d, want 32", len(secret))
	}
}

func TestGenerateHmacSecret_Uniqueness(t *testing.T) {
	secret1, err := anvil.GenerateHmacSecret()
	if err != nil {
		t.Fatalf("GenerateHmacSecret() error = %v", err)
	}

	secret2, err := anvil.GenerateHmacSecret()
	if err != nil {
		t.Fatalf("GenerateHmacSecret() error = %v", err)
	}

	if bytes.Equal(secret1, secret2) {
		t.Error("GenerateHmacSecret() generated duplicate secrets")
	}
}

func TestLoadHmacSecret(t *testing.T) {
	input := []byte("test-secret-key-with-32-bytes!!")
	secret := anvil.LoadHmacSecret(input)

	if !bytes.Equal(secret, input) {
		t.Errorf("LoadHmacSecret() = %v, want %v", secret, input)
	}
}

func TestNewHmacSigner(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)

	if signer == nil {
		t.Fatal("NewHmacSigner() returned nil")
	}
}

func TestHmacSigner_Algorithm(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)

	if got := signer.Algorithm(); got != anvil.Hmac {
		t.Errorf("HmacSigner.Algorithm() = %v, want %v", got, anvil.Hmac)
	}
}

func TestHmacSigner_Sign(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)
	data := []byte("test data")

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	if len(sig) == 0 {
		t.Error("HmacSigner.Sign() returned empty signature")
	}
}

func TestHmacSigner_Sign_Deterministic(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)
	data := []byte("test data")

	sig1, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	sig2, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	if !bytes.Equal(sig1, sig2) {
		t.Error("HmacSigner.Sign() is not deterministic")
	}
}

func TestHmacSigner_Sign_DifferentData(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)

	sig1, err := signer.Sign([]byte("data1"))
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	sig2, err := signer.Sign([]byte("data2"))
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Error("HmacSigner.Sign() produced same signature for different data")
	}
}

func TestHmacSigner_Sign_EmptyData(t *testing.T) {
	secret := []byte("test-secret")
	signer := anvil.NewHmacSigner(secret)

	sig, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatalf("HmacSigner.Sign() error = %v", err)
	}

	if len(sig) == 0 {
		t.Error("HmacSigner.Sign() returned empty signature for empty data")
	}
}

func TestGenerateEcdsaPrivateKey(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateEcdsaPrivateKey() returned nil")
	}

	if key.PublicKey.Curve == nil {
		t.Error("GenerateEcdsaPrivateKey() generated key with nil curve")
	}
}

func TestGenerateEcdsaPrivateKey_Uniqueness(t *testing.T) {
	key1, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	key2, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	bytes1, err := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(key1))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	bytes2, err := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(key2))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	if bytes.Equal(bytes1, bytes2) {
		t.Error("GenerateEcdsaPrivateKey() generated duplicate keys")
	}
}

func TestLoadEcdsaPrivatekey(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(key))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	loaded, err := anvil.LoadEcdsaPrivatekey(keyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPrivatekey() error = %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadEcdsaPrivatekey() returned nil")
	}

	loadedBytes, err := x509.MarshalPKCS8PrivateKey((*ecdsa.PrivateKey)(loaded))
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	if !bytes.Equal(loadedBytes, keyBytes) {
		t.Error("LoadEcdsaPrivatekey() loaded different key")
	}
}

func TestLoadEcdsaPrivatekey_Invalid(t *testing.T) {
	invalid := []byte("invalid key data")

	_, err := anvil.LoadEcdsaPrivatekey(invalid)
	if err == nil {
		t.Fatal("LoadEcdsaPrivatekey() expected error for invalid data")
	}
}

func TestNewEcdsaSigner(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	if signer == nil {
		t.Fatal("NewEcdsaSigner() returned nil")
	}
}

func TestEcdsaSigner_Algorithm(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	if got := signer.Algorithm(); got != anvil.Ecdsa {
		t.Errorf("EcdsaSigner.Algorithm() = %v, want %v", got, anvil.Ecdsa)
	}
}

func TestEcdsaSigner_PublicKey(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("EcdsaSigner.PublicKey() error = %v", err)
	}

	if len(pubKey) == 0 {
		t.Error("EcdsaSigner.PublicKey() returned empty bytes")
	}
}

func TestEcdsaSigner_Sign(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("EcdsaSigner.Sign() error = %v", err)
	}

	if len(sig) == 0 {
		t.Error("EcdsaSigner.Sign() returned empty signature")
	}
}

func TestEcdsaSigner_Sign_EmptyData(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	sig, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatalf("EcdsaSigner.Sign() error = %v", err)
	}

	if len(sig) == 0 {
		t.Error("EcdsaSigner.Sign() returned empty signature for empty data")
	}
}

func TestEcdsaSigner_Sign_NonDeterministic(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	data := []byte("test data")
	sig1, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("EcdsaSigner.Sign() error = %v", err)
	}

	sig2, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("EcdsaSigner.Sign() error = %v", err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Error("EcdsaSigner.Sign() should produce different signatures due to randomness")
	}
}
