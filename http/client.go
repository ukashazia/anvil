package http

import (
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

type Client struct {
	cfg Config
	id  string
}

type Config struct {
	signer     anvil.Signer
	verifier   anvil.Verifier
	nonceStore anvil.NonceStorer
}

type Option func(*Config)

func WithHmacSigner(secret string) Option {
	return func(c *Config) {

		s := anvil.LoadHmacSecret([]byte(secret))
		c.signer = anvil.NewHmacSigner(s)
	}
}

func NewClient(id string, opts ...Option) *Client {
	cfg := &Config{}

	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		cfg: *cfg,
		id:  id,
	}
}

func (c *Client) Sign(req *http.Request, clientId string) *http.Request {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}

	nonce := anvil.GetNonce()
	time := strconv.Itoa(int(time.Now().UnixMilli()))

	sig, err := sign(c.cfg.signer, []byte(nonce), []byte(time), []byte(clientId), body)
	if err != nil {
		return nil
	}

	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerReqTime, time)
	req.Header.Set(headerClientId, c.id)
	req.Header.Set(headerReqSig, string(sig))

	return req
}

func sign(signer anvil.Signer, nonce []byte, t []byte, clientId []byte, body []byte) ([]byte, error) {
	canonical := append(nonce, t...)
	canonical = append(canonical, t...)
	canonical = append(canonical, clientId...)
	canonical = append(canonical, body...)

	s, err := signer.Sign(canonical)
	if err != nil {
		return nil, nil
	}

	return s, nil
}
