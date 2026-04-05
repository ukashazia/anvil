package anvil

import "errors"

var NoPublicKeyError = errors.New("no public key found for the given key")
var NoNonceError = errors.New("no nonce exists for the client")
var NonceExists = errors.New("nonce already exists")
var NoSharedSecretError = errors.New("no shared secret found for the given key")
var NoKeyError = errors.New("no key found for the given key")
var AlgorithmNotSupported = errors.New("algorithm not supported")
