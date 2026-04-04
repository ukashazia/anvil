package anvil_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/ukashazia/anvil/pkg/anvil"
)

func TestLoadEcdsaPublicKey(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	loaded, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadEcdsaPublicKey() returned nil")
	}
}

func TestLoadEcdsaPublicKey_Invalid(t *testing.T) {
	invalid := []byte("invalid public key data")

	_, err := anvil.LoadEcdsaPublicKey(invalid)
	if err == nil {
		t.Fatal("LoadEcdsaPublicKey() expected error for invalid data")
	}
}

func TestNewEcdsaVerifier(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	if verifier == nil {
		t.Fatal("NewEcdsaVerifier() returned nil")
	}
}

func TestEcdsaVerifier_Algorithm(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	if got := verifier.Algorithm(); got != anvil.Ecdsa {
		t.Errorf("EcdsaVerifier.Algorithm() = %v, want %v", got, anvil.Ecdsa)
	}
}

func TestEcdsaVerifier_Verify_Valid(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	hash := sha256.Sum256(data)
	valid, err := verifier.Verify(hash[:], sig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() = false, want true for valid signature")
	}
}

func TestEcdsaVerifier_Verify_Invalid(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	data := []byte("test data")
	hash := sha256.Sum256(data)
	invalidSig := []byte("invalid signature")

	valid, err := verifier.Verify(hash[:], invalidSig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for invalid signature")
	}
}

func TestEcdsaVerifier_Verify_WrongData(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	differentData := []byte("different data")
	hash := sha256.Sum256(differentData)

	valid, err := verifier.Verify(hash[:], sig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for signature on different data")
	}
}

func TestHmacVerifier_Verify_Valid(t *testing.T) {
	secret := []byte("test-secret-key")
	signer := anvil.NewHmacSigner(secret)

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := anvil.NewHmacSigner(secret)
	expectedSig, err := verifier.Sign(data)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Error("HMAC signatures should match with same secret")
	}
}

func TestHmacVerifier_Algorithm(t *testing.T) {
	verifier := &anvil.HmacVerifier{}

	if got := verifier.Algorithm(); got != anvil.Hmac {
		t.Errorf("HmacVerifier.Algorithm() = %v, want %v", got, anvil.Hmac)
	}
}

func TestHmacVerifier_Verify_Invalid(t *testing.T) {
	verifier := &anvil.HmacVerifier{}

	data := []byte("test data")
	invalidSig := []byte("invalid signature")

	valid, err := verifier.Verify(data, invalidSig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for invalid signature")
	}
}

func TestHmacVerifier_Verify_EmptySignature(t *testing.T) {
	verifier := &anvil.HmacVerifier{}

	data := []byte("test data")
	emptySig := []byte{}

	valid, err := verifier.Verify(data, emptySig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for empty signature")
	}
}

func TestHmacVerifier_Verify_DifferentSecrets(t *testing.T) {
	secret1 := []byte("secret1")
	secret2 := []byte("secret2")

	signer := anvil.NewHmacSigner(secret1)
	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier2 := anvil.NewHmacSigner(secret2)
	sig2, err := verifier2.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if bytes.Equal(sig, sig2) {
		t.Error("Different secrets produced same signature")
	}
}

func TestEcdsaVerifier_Verify_EmptySignature(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	data := []byte("test data")
	hash := sha256.Sum256(data)
	emptySig := []byte{}

	valid, err := verifier.Verify(hash[:], emptySig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for empty signature")
	}
}

func TestEcdsaVerifier_Verify_WrongKey(t *testing.T) {
	key1, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	key2, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer, err := anvil.NewEcdsaSigner(key1)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	data := []byte("test data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signer2, err := anvil.NewEcdsaSigner(key2)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes2, err := signer2.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey2, err := anvil.LoadEcdsaPublicKey(pubKeyBytes2)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey2)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	hash := sha256.Sum256(data)
	valid, err := verifier.Verify(hash[:], sig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if valid {
		t.Error("Verify() = true, want false for signature from different key")
	}
}
