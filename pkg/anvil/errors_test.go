package anvil_test

import (
	"errors"
	"testing"

	"github.com/ukashazia/anvil/pkg/anvil"
)

func TestNoPublicKeyError(t *testing.T) {
	if anvil.NoPublicKeyError == nil {
		t.Fatal("NoPublicKeyError should not be nil")
	}

	expected := "no public key found for the given key"
	if anvil.NoPublicKeyError.Error() != expected {
		t.Errorf("NoPublicKeyError message = %q, want %q", anvil.NoPublicKeyError.Error(), expected)
	}

	if !errors.Is(anvil.NoPublicKeyError, anvil.NoPublicKeyError) {
		t.Error("errors.Is should match NoPublicKeyError")
	}
}

func TestNoNonceError(t *testing.T) {
	if anvil.NoNonceError == nil {
		t.Fatal("NoNonceError should not be nil")
	}

	expected := "no nonce exists for the client"
	if anvil.NoNonceError.Error() != expected {
		t.Errorf("NoNonceError message = %q, want %q", anvil.NoNonceError.Error(), expected)
	}

	if !errors.Is(anvil.NoNonceError, anvil.NoNonceError) {
		t.Error("errors.Is should match NoNonceError")
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	if errors.Is(anvil.NoPublicKeyError, anvil.NoNonceError) {
		t.Error("NoPublicKeyError and NoNonceError should be distinct")
	}

	if errors.Is(anvil.NoNonceError, anvil.NoPublicKeyError) {
		t.Error("NoNonceError and NoPublicKeyError should be distinct")
	}
}
