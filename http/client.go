package http

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ukashazia/anvil"
	"github.com/ukashazia/anvil/internal"
)

const headerNonce = "X-Nonce"
const headerReqTime = "X-Request-Time"
const headerReqSig = "X-Request-Signature"
const headerClientID = "X-ClientID"
const headerSigAlgo = "X-Signature-Algorithm"

type client struct {
	cfg config
	id  string
}

type config struct {
	signer     anvil.Signer
	verifier   anvil.Verifier
	nonceStore anvil.NonceStorer
	keyStore   anvil.KeyStorer
}

type clientConfig func(*client) error

func WithEcdsaSigner(key internal.PrivateKey) clientConfig {
	return func(c *client) error {

		signer, err := anvil.NewEcdsaSigner(key)
		if err != nil {
			return err
		}

		c.cfg.signer = signer
		return nil
	}
}

func WithHmacSigner(secret internal.HmacSecret) clientConfig {
	return func(c *client) error {

		c.cfg.signer = anvil.NewHmacSigner(secret)

		return nil
	}
}

func NewClient(id string, opts ...clientConfig) (*client, error) {
	c := &client{
		id: id,
	}

	for _, opt := range opts {
		err := opt(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *client) Sign(req *http.Request) (*http.Request, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	err = req.Body.Close()
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewReader(body))

	nonce, err := anvil.GetNonce()
	if err != nil {
		return nil, err
	}

	time := strconv.Itoa(int(time.Now().UnixMilli()))

	e := signatureElements{
		nonce:    nonce,
		t:        time,
		clientID: c.id,
		body:     body,
		signer:   c.cfg.signer,
	}

	sig, err := e.sign()
	if err != nil {
		return nil, err
	}

	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerReqTime, time)
	req.Header.Set(headerClientID, c.id)
	req.Header.Set(headerSigAlgo, c.cfg.signer.Algorithm().String())
	req.Header.Set(headerReqSig, hex.EncodeToString(sig))

	return req, nil
}
