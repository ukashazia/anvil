package anvil

import "errors"

var ErrNoPublicKey = errors.New("no public key found for the given key")
var ErrNoNonce = errors.New("no nonce exists for the client")
var ErrNonceExists = errors.New("nonce already exists")
var ErrNoSharedSecret = errors.New("no shared secret found for the given key")
var ErrNoKey = errors.New("no key found for the given key")
var ErrAlgorithmNotSupported = errors.New("algorithm not supported")

var ErrUnsupportedPrivateKeyType = errors.New("unsupported private key type")
var ErrUnsupportedPublicKeyType = errors.New("unsupported public key type")
