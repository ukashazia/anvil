package http

import (
	"encoding/hex"

	"github.com/ukashazia/anvil"
)

func (e *signatureElements) sign() ([]byte, error) {
	s, err := e.signer.Sign(e.buildCanonical())
	if err != nil {
		return nil, err
	}

	return s, nil
}

type signatureElements struct {
	nonce    string
	t        string
	clientID string
	body     []byte
	signer   anvil.Signer
	verifier anvil.Verifier
}

func (c *signatureElements) buildCanonical() []byte {
	canonical := append([]byte(c.nonce), c.t...)
	canonical = append(canonical, c.clientID...)
	canonical = append(canonical, c.body...)

	return canonical
}

func (e *signatureElements) verify(sig string) (bool, error) {

	sigDecoded, err := hex.DecodeString(sig)
	if err != nil {
		return false, err
	}
	canonical := e.buildCanonical()

	v, err := e.verifier.Verify(canonical, sigDecoded)
	if err != nil {
		return false, err
	}

	return v, nil
}
