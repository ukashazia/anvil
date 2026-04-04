i'm too tired to write what i did :)

well, here's what the clanker (and me) summarized:


# anvil

Anvil is a lightweight Go library for request authenticity and replay protection.
It provides signing, verification, nonce validation, and public key storage primitives, with an experimental HTTP layer.

## Status

This project is actively evolving and parts of the API are still work in progress.

- Core crypto and store primitives are usable.
- The `http` package is experimental and should be treated as unstable.

## Install

```bash
go get github.com/ukashazia/anvil
```

## What it provides

- HMAC-SHA256 signing and verification
- ECDSA P-256 signing and verification
- Nonce generation and TTL-based validation
- In-memory public key store
- Experimental HTTP client signer and verification middleware

## Usage

### 1) HMAC sign and verify

```go
package main

import (
	"fmt"

	"github.com/ukashazia/anvil"
)

func main() {
	secret, err := anvil.GenerateHmacSecret()
	if err != nil {
		panic(err)
	}

	signer := anvil.NewHmacSigner(secret)
	verifier := anvil.NewHmacVerifier(secret)

	msg := []byte("hello anvil")
	sig, err := signer.Sign(msg)
	if err != nil {
		panic(err)
	}

	ok, err := verifier.Verify(msg, sig)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}
```

### 2) ECDSA sign and verify

```go
package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/ukashazia/anvil"
)

func main() {
	priv, err := anvil.GenerateEcdsaPrivateKey()
	if err != nil {
		panic(err)
	}

	signer, err := anvil.NewEcdsaSigner(priv)
	if err != nil {
		panic(err)
	}

	pubBytes, err := signer.PublicKey()
	if err != nil {
		panic(err)
	}

	pub, err := anvil.LoadEcdsaPublicKey(pubBytes)
	if err != nil {
		panic(err)
	}

	verifier, err := anvil.NewEcdsaVerifier(pub)
	if err != nil {
		panic(err)
	}

	msg := []byte("hello anvil")
	sig, err := signer.Sign(msg)
	if err != nil {
		panic(err)
	}

	h := sha256.Sum256(msg)
	ok, err := verifier.Verify(h[:], sig)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}
```

### 3) Nonce store

```go
package main

import (
	"fmt"
	"time"

	"github.com/ukashazia/anvil"
)

func main() {
	ns := anvil.NewNonceStore(30 * time.Second)
	n := anvil.GetNonce()

	if err := ns.Set("client-1", n); err != nil {
		panic(err)
	}

	ok, err := ns.Valid("client-1", n)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
}
```

### 4) Key store

```go
package main

import (
	"fmt"

	"github.com/ukashazia/anvil"
)

func main() {
	ks, err := anvil.NewKeyStore()
	if err != nil {
		panic(err)
	}

	if err := ks.SetPublicKey("client-1", []byte("public-key-bytes")); err != nil {
		panic(err)
	}

	k, err := ks.GetPublicKey("client-1")
	if err != nil {
		panic(err)
	}

	fmt.Println(len(k) > 0)
}
```

### 5) HTTP package (experimental)

```go
package main

import (
	"bytes"
	"net/http"
	"time"

	"github.com/ukashazia/anvil"
	anvilhttp "github.com/ukashazia/anvil/http"
)

func main() {
	secret := "shared-secret"
	nonceStore := anvil.NewNonceStore(30 * time.Second)

	client := anvilhttp.NewClient(
		"client-1",
		anvilhttp.WithHmacSigner(secret),
	)

	mw := anvilhttp.NewMiddleware(
		anvilhttp.WithHmacSigner(secret),
		anvilhttp.WithHmacVerifier(secret),
		anvilhttp.WithNonceStore(nonceStore),
	)
	if err != nil {
		panic(err)
	}

	payload := []byte(`{"ping":"pong"}`)
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080", bytes.NewReader(payload))
	req = client.Sign(req, "client-1")

	_ = mw
	_ = req
}
```

## Work in progress

### Core package

- Better typed errors and error wrapping for easier troubleshooting.
- Stronger input validation paths for key parsing.
- Optional persistent/backed stores beyond in-memory maps.
- Keystore for Ecdsa signing keys

### `http` package (important)

- Canonical payload still omits method, path, and query, so request-target tampering is not covered.
- HMAC options exist, but ECDSA options are not exposed in the `http` option surface yet.

## Roadmap

- Harden middleware config validation and startup checks.
- Improve nonce replay policy and cleanup strategy.
- Add integration test matrix across HMAC and ECDSA HTTP flows.
- Add interoperability examples for service-to-service auth.

- Introduce pluggable key resolution (static, in-memory, remote).
- Add versioned canonicalization format for backwards compatibility.
- Publish a security guide and threat model notes.

## Contributing

If you want to contribute, open an issue with the target area (`core`, `http`, `tests`, `docs`) and a short design note before implementation.

