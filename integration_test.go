package anvil_test

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ukashazia/anvil"
)

func TestHmacSignVerify_Integration(t *testing.T) {
	secret, err := anvil.GenerateHmacSecret()
	if err != nil {
		t.Fatalf("GenerateHmacSecret() error = %v", err)
	}

	signer := anvil.NewHmacSigner(secret)

	data := []byte("test message for signing")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := anvil.NewHmacSigner(secret)
	expectedSig, err := verifier.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Error("HMAC signatures should match with same secret")
	}
}

func TestEcdsaSignVerify_Integration(t *testing.T) {
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

	data := []byte("test message for signing")
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

func TestEcdsaSignVerify_MultipleMessages(t *testing.T) {
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

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
		[]byte(""),
		[]byte("a very long message that contains lots of data to test signature verification"),
	}

	for _, msg := range messages {
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		hash := sha256.Sum256(msg)
		valid, err := verifier.Verify(hash[:], sig)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		if !valid {
			t.Errorf("Verify() = false for message %q, want true", msg)
		}
	}
}

func TestKeyStore_WithEcdsaKeys(t *testing.T) {
	store, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key1, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	key2, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer1, err := anvil.NewEcdsaSigner(key1)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	signer2, err := anvil.NewEcdsaSigner(key2)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKey1, err := signer1.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	pubKey2, err := signer2.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	if err := store.SetKey("client1", anvil.Ecdsa, pubKey1); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}
	if err := store.SetKey("client2", anvil.Ecdsa, pubKey2); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	retrievedKey1, err := store.GetKey("client1", anvil.Ecdsa)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	retrievedKey2, err := store.GetKey("client2", anvil.Ecdsa)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if !bytes.Equal(retrievedKey1, pubKey1) {
		t.Error("Retrieved key1 does not match stored key1")
	}

	if !bytes.Equal(retrievedKey2, pubKey2) {
		t.Error("Retrieved key2 does not match stored key2")
	}
}

func TestFullWorkflow_EcdsaWithKeyStoreAndNonce(t *testing.T) {
	keyStore, err := anvil.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	nonceStore := anvil.NewNonceStore(5 * time.Second)

	serverKey, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	clientKey, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	serverSigner, err := anvil.NewEcdsaSigner(serverKey)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	clientSigner, err := anvil.NewEcdsaSigner(clientKey)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	serverPubKey, err := serverSigner.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	clientPubKey, err := clientSigner.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	if err := keyStore.SetKey("server", anvil.Ecdsa, serverPubKey); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}
	if err := keyStore.SetKey("client", anvil.Ecdsa, clientPubKey); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	nonce := anvil.GetNonce()
	if err := nonceStore.Mark(nonce); err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	message := []byte("authenticated request from client")
	clientSig, err := clientSigner.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	retrievedClientPubKey, err := keyStore.GetKey("client", anvil.Ecdsa)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	clientPub, err := anvil.LoadEcdsaPublicKey(retrievedClientPubKey)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(clientPub)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	hash := sha256.Sum256(message)
	valid, err := verifier.Verify(hash[:], clientSig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Verify() = false, want true for valid client signature")
	}

	err = nonceStore.Mark(nonce)
	if err != nil {
		t.Fatalf("Mark() error = %v", err)
	}

	time.Sleep(6 * time.Second)

	err = nonceStore.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	err = nonceStore.Mark(nonce)
	if err != nil {
		t.Fatalf("Mark() after Prune() error = %v", err)
	}
}

func TestAlgorithm_Consistency(t *testing.T) {
	hmacSecret, err := anvil.GenerateHmacSecret()
	if err != nil {
		t.Fatalf("GenerateHmacSecret() error = %v", err)
	}

	ecdsaKey, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	hmacSigner := anvil.NewHmacSigner(hmacSecret)
	ecdsaSigner, err := anvil.NewEcdsaSigner(ecdsaKey)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	if hmacSigner.Algorithm() == ecdsaSigner.Algorithm() {
		t.Error("HMAC and ECDSA should have different algorithms")
	}

	if hmacSigner.Algorithm().String() != "hmac" {
		t.Errorf("HMAC algorithm string = %q, want %q", hmacSigner.Algorithm().String(), "hmac")
	}

	if ecdsaSigner.Algorithm().String() != "ecdsa" {
		t.Errorf("ECDSA algorithm string = %q, want %q", ecdsaSigner.Algorithm().String(), "ecdsa")
	}
}

func TestEcdsaKeyPersistence(t *testing.T) {
	key, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEcdsaPrivateKey() error = %v", err)
	}

	signer1, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes, err := signer1.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	data := []byte("test data")
	sig, err := signer1.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signer2, err := anvil.NewEcdsaSigner(key)
	if err != nil {
		t.Fatalf("NewEcdsaSigner() error = %v", err)
	}

	pubKeyBytes2, err := signer2.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	if !bytes.Equal(pubKeyBytes, pubKeyBytes2) {
		t.Error("Same private key should produce same public key bytes")
	}

	pubKey, err := anvil.LoadEcdsaPublicKey(pubKeyBytes)
	if err != nil {
		t.Fatalf("LoadEcdsaPublicKey() error = %v", err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewEcdsaVerifier() error = %v", err)
	}

	hash := sha256.Sum256(data)
	valid, err := verifier.Verify(hash[:], sig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !valid {
		t.Error("Signature should be valid after key persistence")
	}
}
