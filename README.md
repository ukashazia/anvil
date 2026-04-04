i'm too tired to write what i did :)

well, here what the clanker summarized:


Anvil is a Go module (github.com/ukashazia/anvil) focused on application-layer request authenticity and replay protection.

It defines a small set of crypto and state abstractions — Signer, Verifier, NonceStorer, and KeyStorer — and ships concrete implementations for HMAC-SHA256 and ECDSA (P-256).

The core package supports generating/loading secrets and keys, signing payloads, verifying signatures, issuing nonces, and tracking nonce validity with TTL semantics.

It also includes an HTTP layer (http/client.go, http/middleware.go) that applies these primitives to outgoing/incoming requests via headers like X-Nonce, X-Request-Time, X-Request-Signature, and X-ClientId.

In practice, the client canonicalizes request metadata + body, signs it, and attaches headers; middleware reconstructs the same canonical representation, enforces freshness/nonce validity, verifies signature integrity, and authorizes or rejects the request.

The project is structured as a compact security utility library intended to be embedded into services that need signed request workflows with minimal integration overhead.
