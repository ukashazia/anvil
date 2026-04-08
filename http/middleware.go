package http

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ukashazia/anvil"
)

type middleware struct {
	cfg config
	ttl time.Duration
}

type middlewareConfig func(*middleware)

func NewMiddleware(opts ...middlewareConfig) (*middleware, error) {
	m := &middleware{
		ttl: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(m)
	}

	if m.cfg.verifier != nil {
		return nil, errors.New("verifier is not required")
	}
	if m.cfg.nonceStore == nil {
		return nil, errors.New("nonce store is required")
	}
	if m.cfg.signer != nil {

		return nil, errors.New("signer is not required")
	}
	if m.cfg.keyStore == nil {
		return nil, errors.New("key store is required")
	}

	return m, nil
}

func WithTtl(ttl time.Duration) middlewareConfig {
	return func(m *middleware) {
		m.ttl = ttl
	}
}

func WithNonceStore(ns anvil.NonceStorer) middlewareConfig {
	return func(m *middleware) {
		m.cfg.nonceStore = ns
	}
}

func WithKeyStore(ks anvil.KeyStorer) middlewareConfig {
	return func(m *middleware) {
		m.cfg.keyStore = ks
	}
}

func (m *middleware) Verify(handler http.Handler) http.Handler {
	return chain(handler, m.validateTimeout, m.validateNonce, m.validateSignature)
}

func (m *middleware) validateNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(headerNonce)
		err := m.cfg.nonceStore.Mark(nonce)
		if err != nil && errors.Is(err, anvil.ErrNonceExists) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *middleware) validateTimeout(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqTime, err := strconv.Atoi(r.Header.Get(headerReqTime))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if time.Now().UnixMilli()-int64(reqTime) > m.ttl.Milliseconds() {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *middleware) validateSignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		sigAlgo := r.Header.Get(headerSigAlgo)
		clientID := r.Header.Get(headerClientID)
		algo, err := anvil.GetAlgorithmFromString(sigAlgo)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		v, err := m.determineVerifier(clientID, algo)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		e := signatureElements{
			nonce:    r.Header.Get(headerNonce),
			t:        r.Header.Get(headerReqTime),
			clientID: clientID,
			body:     body,
			verifier: v,
		}

		valid, err := e.verify(signature)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

func (m *middleware) determineVerifier(clientID string, algorithm anvil.Algorithm) (anvil.Verifier, error) {
	switch algorithm {
	case anvil.Hmac:
		secret, err := m.cfg.keyStore.GetKey(clientID, algorithm)
		if err != nil {
			return nil, err
		}

		return anvil.NewHmacVerifier(secret), nil
	case anvil.Ecdsa:
		key, err := m.cfg.keyStore.GetKey(clientID, algorithm)
		if err != nil {
			return nil, err
		}

		pubKey, err := anvil.LoadEcdsaPublicKey(key)
		if err != nil {
			return nil, err
		}

		v, err := anvil.NewEcdsaVerifier(pubKey)
		if err != nil {
			return nil, err
		}

		return v, nil
	default:
		return nil, anvil.ErrAlgorithmNotSupported
	}
}
