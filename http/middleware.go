package http

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ukashazia/anvil"
)

type Middleware struct {
	cfg Config
}

func NewMiddleware(opts ...Option) *Middleware {
	cfg := &Config{}

	for _, opt := range opts {
		opt(cfg)
	}

	return &Middleware{
		cfg: *cfg,
	}
}

func WithHmacVerifier(secret string) Option {
	return func(c *Config) {
		c.verifier = anvil.NewHmacVerifier(anvil.LoadHmacSecret([]byte(secret)))
	}
}

func WithNonceStore(ns anvil.NonceStorer) Option {
	return func(c *Config) {
		c.nonceStore = ns
	}
}

func (m *Middleware) Verify(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		reqTime, err := strconv.Atoi(r.Header.Get(headerReqTime))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		clientId := r.Header.Get(headerClientId)
		nonce := r.Header.Get(headerNonce)

		if time.Now().UnixMilli()-int64(reqTime) > 30*1000 {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}

		if valid, err := m.cfg.nonceStore.Valid(clientId, nonce); err != nil || !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = r.Body.Close()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))

		valid, err := verify(m.cfg.verifier, []byte(r.Header.Get(headerReqSig)), []byte(r.Header.Get(headerNonce)), []byte(r.Header.Get(headerReqTime)), []byte(r.Header.Get(headerClientId)), []byte(body))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func verify(signer anvil.Verifier, sig []byte, nonce []byte, t []byte, clientId []byte, body []byte) (bool, error) {
	canonical := append(nonce, t...)
	canonical = append(canonical, t...)
	canonical = append(canonical, clientId...)
	canonical = append(canonical, body...)

	v, err := signer.Verify(canonical, sig)
	if err != nil {
		return false, nil
	}

	return v, nil
}
