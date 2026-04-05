package anvil

import "errors"

var NoPublicKeyError = errors.New("no public key found for the given key")
var NoNonceError = errors.New("no nonce exists for the client")
var NonceExists = errors.New("nonce already exists")
