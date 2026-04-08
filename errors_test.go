package anvil_test

import (
	"errors"
	"testing"

	"github.com/ukashazia/anvil"
)

func ErrNoPublicKey(t *testing.T) {
	if anvil.ErrNoPublicKey == nil {
		t.Fatal("ErrNoPublicKey should not be nil")
	}

	expected := "no public key found for the given key"
	if anvil.ErrNoPublicKey.Error() != expected {
		t.Errorf("ErrNoPublicKey message = %q, want %q", anvil.ErrNoPublicKey.Error(), expected)
	}

	if !errors.Is(anvil.ErrNoPublicKey, anvil.ErrNoPublicKey) {
		t.Error("errors.Is should match ErrNoPublicKey")
	}
}

func TestNoNonceError(t *testing.T) {
	if anvil.ErrNoNonce == nil {
		t.Fatal("ErrNoNonce should not be nil")
	}

	expected := "no nonce exists for the client"
	if anvil.ErrNoNonce.Error() != expected {
		t.Errorf("ErrNoNonce message = %q, want %q", anvil.ErrNoNonce.Error(), expected)
	}

	if !errors.Is(anvil.ErrNoNonce, anvil.ErrNoNonce) {
		t.Error("errors.Is should match ErrNoNonce")
	}
}

func TestNonceExists(t *testing.T) {
	if anvil.ErrNonceExists == nil {
		t.Fatal("ErrNonceExists should not be nil")
	}

	expected := "nonce already exists"
	if anvil.ErrNonceExists.Error() != expected {
		t.Errorf("ErrNonceExists message = %q, want %q", anvil.ErrNonceExists.Error(), expected)
	}

	if !errors.Is(anvil.ErrNonceExists, anvil.ErrNonceExists) {
		t.Error("errors.Is should match ErrNonceExists")
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	if errors.Is(anvil.ErrNoPublicKey, anvil.ErrNoNonce) {
		t.Error("ErrNoPublicKey and ErrNoNonce should be distinct")
	}

	if errors.Is(anvil.ErrNoNonce, anvil.ErrNoPublicKey) {
		t.Error("ErrNoNonce and ErrNoPublicKey should be distinct")
	}

	if errors.Is(anvil.ErrNonceExists, anvil.ErrNoPublicKey) {
		t.Error("ErrNonceExists and ErrNoPublicKey should be distinct")
	}

	if errors.Is(anvil.ErrNonceExists, anvil.ErrNoNonce) {
		t.Error("ErrNonceExists and ErrNoNonce should be distinct")
	}
}
