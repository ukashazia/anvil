package anvil

import "errors"

var NoPublicKeyError = errors.New("no public key found for the given key")
var NoNonceError = errors.New("no nonce exists for the client")
var DuplicateNonce = errors.New("duplicate nonce found in nonce store")
