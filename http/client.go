package http

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ukashazia/anvil"
)

const headerNonce = "X-Nonce"
const headerReqTime = "X-Request-Time"
const headerReqSig = "X-Request-Signature"
const headerClientId = "X-ClientId"

type client struct {
	cfg config
	id  string
}

type config struct {
	signer     anvil.Signer
	verifier   anvil.Verifier
	nonceStore anvil.NonceStorer
}

type clientConfig func(*client)

func WithHmacSigner(secret string) clientConfig {
	return func(c *client) {

		s := anvil.LoadHmacSecret([]byte(secret))
		c.cfg.signer = anvil.NewHmacSigner(s)
	}
}

func NewClient(id string, opts ...clientConfig) *client {
	c := &client{
		id: id,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *client) Sign(req *http.Request) *http.Request {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}

	err = req.Body.Close()
	if err != nil {
		return nil
	}

	req.Body = io.NopCloser(bytes.NewReader(body))

	nonce := anvil.GetNonce()
	time := strconv.Itoa(int(time.Now().UnixMilli()))

	e := signatureElements{
		nonce:    nonce,
		t:        time,
		clientId: c.id,
		body:     body,
		signer:   c.cfg.signer,
	}

	sig, err := e.sign()
	if err != nil {
		return nil
	}

	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerReqTime, time)
	req.Header.Set(headerClientId, c.id)
	req.Header.Set(headerReqSig, hex.EncodeToString(sig))

	return req
}
