package http

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ukashazia/anvil"
)

type Middleware struct {
	cfg Config
}

func NewMiddleware(opts ...Option) (*Middleware, error) {
	cfg := &Config{}

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.verifier == nil {
		return nil, errors.New("verifier is required")
	}
	if cfg.nonceStore == nil {
		return nil, errors.New("nonce store is required")
	}
	if cfg.signer == nil {
		return nil, errors.New("signer is required")
	}

	return &Middleware{
		cfg: *cfg,
	}, nil
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

		valid, err := m.cfg.nonceStore.Valid(clientId, nonce)
		if err != nil && errors.Is(err, anvil.NoNonceError) {
			err := m.cfg.nonceStore.Set(clientId, nonce)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if err == nil && !valid {
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

		signature := r.Header.Get(headerReqSig)
		if signature == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sig, err := hex.DecodeString(signature)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		valid, err = verify(m.cfg.verifier, sig, []byte(r.Header.Get(headerNonce)), []byte(r.Header.Get(headerReqTime)), []byte(r.Header.Get(headerClientId)), body)
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
	canonical = append(canonical, clientId...)
	canonical = append(canonical, body...)

	v, err := signer.Verify(canonical, sig)
	if err != nil {
		return false, err
	}

	return v, nil
}
