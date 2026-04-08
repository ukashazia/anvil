package anvil

import "crypto/ecdsa"

type Algorithm int

const (
	Hmac Algorithm = iota
	Ecdsa
)

var supportedAlgorithms = []string{
	"hmac",
	"ecdsa",
}

func (a Algorithm) String() string {
	return supportedAlgorithms[a]
}

func GetAlgorithmFromString(s string) (Algorithm, error) {
	switch s {
	case "hmac":
		return Hmac, nil
	case "ecdsa":
		return Ecdsa, nil
	default:
		return -1, ErrAlgorithmNotSupported
	}
}

type HmacSecret []byte
type PrivateKey ecdsa.PrivateKey
type PublicKey ecdsa.PublicKey
