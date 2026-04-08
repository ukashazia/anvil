package http

import (
	"bytes"
	"errors"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ukashazia/anvil"
)

type stubNonceStore struct {
	err error
}

func (s *stubNonceStore) Mark(_ string) error {
	return s.err
}

func (s *stubNonceStore) Prune() error {
	return nil
}

type stubVerifier struct {
	valid   bool
	err     error
	msg     []byte
	sig     []byte
	invoked bool
}

func (s *stubVerifier) Verify(msg []byte, sig []byte) (bool, error) {
	s.invoked = true
	s.msg = append([]byte(nil), msg...)
	s.sig = append([]byte(nil), sig...)
	if s.err != nil {
		return false, s.err
	}
	return s.valid, nil
}

func (s *stubVerifier) Algorithm() anvil.Algorithm {
	return anvil.Hmac
}

type stubSigner struct{}

func (s *stubSigner) Sign(_ []byte) ([]byte, error) {
	return []byte("unused"), nil
}

func (s *stubSigner) Algorithm() anvil.Algorithm {
	return anvil.Hmac
}

type stubKeyStore struct {
	keys map[string][]byte
	err  error
}

func newStubKeyStore() *stubKeyStore {
	return &stubKeyStore{keys: map[string][]byte{}}
}

func keyFor(clientID string, algorithm anvil.Algorithm) string {
	return clientID + ":" + algorithm.String()
}

func (s *stubKeyStore) SetKey(clientID string, algorithm anvil.Algorithm, key []byte) error {
	s.keys[keyFor(clientID, algorithm)] = append([]byte(nil), key...)
	return nil
}

func (s *stubKeyStore) GetKey(clientID string, algorithm anvil.Algorithm) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.keys[keyFor(clientID, algorithm)]
	if !ok {
		return nil, anvil.ErrNoKey
	}
	return append([]byte(nil), v...), nil
}

func (s *stubKeyStore) RemoveKey(clientID string, algorithm anvil.Algorithm) error {
	delete(s.keys, keyFor(clientID, algorithm))
	return nil
}

type readErrRequestBody struct{}

func (b *readErrRequestBody) Read(_ []byte) (int, error) {
	return 0, errors.New("read body error")
}

func (b *readErrRequestBody) Close() error {
	return nil
}

type closeErrRequestBody struct {
	r *bytes.Reader
}

func (b *closeErrRequestBody) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *closeErrRequestBody) Close() error {
	return errors.New("close body error")
}

func newValidSignedRequest(t *testing.T, body string, clientID string, secret []byte) *stdhttp.Request {
	t.Helper()

	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString(body))
	c, err := NewClient(clientID, WithHmacSigner(anvil.LoadHmacSecret(secret)))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	signed, err := c.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed
}

func newSuccessfulHandler(called *bool) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		*called = true
		w.WriteHeader(stdhttp.StatusNoContent)
	})
}

func newValidateSignatureRequest(body string, signature string) *stdhttp.Request {
	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set(headerNonce, "n-1")
	req.Header.Set(headerReqTime, strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set(headerClientID, "client-1")
	req.Header.Set(headerSigAlgo, "hmac")
	if signature != "" {
		req.Header.Set(headerReqSig, signature)
	}
	return req
}

func TestNewMiddleware_RequiredDependencies(t *testing.T) {
	tests := []struct {
		name    string
		opts    []middlewareConfig
		wantErr string
	}{
		{
			name: "missing nonce store",
			opts: []middlewareConfig{
				WithKeyStore(newStubKeyStore()),
			},
			wantErr: "nonce store is required",
		},
		{
			name: "missing key store",
			opts: []middlewareConfig{
				WithNonceStore(&stubNonceStore{}),
			},
			wantErr: "key store is required",
		},
		{
			name: "verifier not required",
			opts: []middlewareConfig{
				WithNonceStore(&stubNonceStore{}),
				WithKeyStore(newStubKeyStore()),
				func(m *middleware) { m.cfg.verifier = &stubVerifier{valid: true} },
			},
			wantErr: "verifier is not required",
		},
		{
			name: "signer not required",
			opts: []middlewareConfig{
				WithNonceStore(&stubNonceStore{}),
				WithKeyStore(newStubKeyStore()),
				func(m *middleware) { m.cfg.signer = &stubSigner{} },
			},
			wantErr: "signer is not required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMiddleware(tt.opts...)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("NewMiddleware() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestWithTtl_OverridesDefault(t *testing.T) {
	m, err := NewMiddleware(
		WithNonceStore(&stubNonceStore{}),
		WithKeyStore(newStubKeyStore()),
		WithTtl(5*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	if m.ttl != 5*time.Second {
		t.Fatalf("middleware ttl = %v, want %v", m.ttl, 5*time.Second)
	}
}

func TestWithNonceStore_ConfiguresNonceStore(t *testing.T) {
	ns := &stubNonceStore{}
	m := &middleware{}
	WithNonceStore(ns)(m)

	if m.cfg.nonceStore != ns {
		t.Fatal("WithNonceStore() should assign provided nonce store")
	}
}

func TestWithKeyStore_ConfiguresKeyStore(t *testing.T) {
	ks := newStubKeyStore()
	m := &middleware{}
	WithKeyStore(ks)(m)

	if m.cfg.keyStore != ks {
		t.Fatal("WithKeyStore() should assign provided key store")
	}
}

func TestMiddlewareVerify_AllValid_CallsHandler(t *testing.T) {
	secret := []byte("my-secret")
	keyStore := newStubKeyStore()
	if err := keyStore.SetKey("client-1", anvil.Hmac, secret); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	m, err := NewMiddleware(
		WithNonceStore(anvil.NewNonceStore(time.Minute)),
		WithKeyStore(keyStore),
		WithTtl(10*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	req := newValidSignedRequest(t, "payload", "client-1", secret)

	called := false
	handler := m.Verify(newSuccessfulHandler(&called))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusNoContent)
	}
	if !called {
		t.Fatal("handler should have been called")
	}
}

func TestValidateSignature_ErrorPaths(t *testing.T) {
	keyStore := newStubKeyStore()
	if err := keyStore.SetKey("client-1", anvil.Hmac, []byte("secret")); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	m := &middleware{cfg: config{keyStore: keyStore}}

	tests := []struct {
		name       string
		buildReq   func() *stdhttp.Request
		wantStatus int
	}{
		{
			name:       "missing signature",
			buildReq:   func() *stdhttp.Request { return newValidateSignatureRequest("payload", "") },
			wantStatus: stdhttp.StatusUnauthorized,
		},
		{
			name:       "invalid hex",
			buildReq:   func() *stdhttp.Request { return newValidateSignatureRequest("payload", "not-hex") },
			wantStatus: stdhttp.StatusInternalServerError,
		},
		{
			name: "unsupported signature algorithm",
			buildReq: func() *stdhttp.Request {
				req := newValidateSignatureRequest("payload", "de")
				req.Header.Set(headerSigAlgo, "unknown")
				return req
			},
			wantStatus: stdhttp.StatusInternalServerError,
		},
		{
			name: "body read error",
			buildReq: func() *stdhttp.Request {
				req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
				req.Body = &readErrRequestBody{}
				req.Header.Set(headerReqSig, "de")
				return req
			},
			wantStatus: stdhttp.StatusInternalServerError,
		},
		{
			name: "body close error",
			buildReq: func() *stdhttp.Request {
				req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
				req.Body = &closeErrRequestBody{r: bytes.NewReader([]byte("payload"))}
				req.Header.Set(headerReqSig, "de")
				return req
			},
			wantStatus: stdhttp.StatusInternalServerError,
		},
		{
			name:       "invalid signature",
			buildReq:   func() *stdhttp.Request { return newValidateSignatureRequest("payload", "00") },
			wantStatus: stdhttp.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := m.validateSignature(newSuccessfulHandler(&called))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, tt.buildReq())

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if called {
				t.Fatal("next handler should not be called")
			}
		})
	}
}

func TestValidateSignature_PassesCanonicalMessageAndRestoresBody(t *testing.T) {
	secret := []byte("secret")
	keyStore := newStubKeyStore()
	if err := keyStore.SetKey("client-1", anvil.Hmac, secret); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	m := &middleware{cfg: config{keyStore: keyStore}}
	body := "payload"
	req := newValidSignedRequest(t, body, "client-1", secret)

	called := false
	handler := m.validateSignature(newSuccessfulHandler(&called))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusNoContent)
	}
	if !called {
		t.Fatal("next handler should be called")
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(req.Body) error = %v", err)
	}
	if string(restored) != body {
		t.Fatalf("request body after validateSignature = %q, want %q", string(restored), body)
	}
}

func TestDetermineVerifier(t *testing.T) {
	secret := []byte("secret")
	keyStore := newStubKeyStore()
	if err := keyStore.SetKey("client-1", anvil.Hmac, secret); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	m := &middleware{cfg: config{keyStore: keyStore}}

	v, err := m.determineVerifier("client-1", anvil.Hmac)
	if err != nil {
		t.Fatalf("determineVerifier() error = %v", err)
	}
	if v == nil {
		t.Fatal("determineVerifier() returned nil verifier")
	}

	if _, err := m.determineVerifier("client-1", anvil.Algorithm(999)); !errors.Is(err, anvil.ErrAlgorithmNotSupported) {
		t.Fatalf("determineVerifier() error = %v, want %v", err, anvil.ErrAlgorithmNotSupported)
	}
}

func TestSignatureElementsVerify_BuildsCanonicalMessage(t *testing.T) {
	v := &stubVerifier{valid: true}
	e := signatureElements{
		nonce:    "nonce",
		t:        "time",
		clientID: "client",
		body:     []byte("body"),
		verifier: v,
	}

	valid, err := e.verify("0102")
	if err != nil {
		t.Fatalf("signatureElements.verify() error = %v", err)
	}
	if !valid {
		t.Fatal("signatureElements.verify() = false, want true")
	}

	if got, want := string(v.msg), "noncetimeclientbody"; got != want {
		t.Fatalf("signatureElements.verify() canonical message = %q, want %q", got, want)
	}

	if !bytes.Equal(v.sig, []byte{0x01, 0x02}) {
		t.Fatalf("signatureElements.verify() signature = %v, want %v", v.sig, []byte{0x01, 0x02})
	}
}

func TestSignatureElementsVerify_PropagatesVerifierError(t *testing.T) {
	e := signatureElements{
		nonce:    "n",
		t:        "t",
		clientID: "c",
		body:     []byte("b"),
		verifier: &stubVerifier{err: errors.New("boom")},
	}

	_, err := e.verify("01")
	if err == nil {
		t.Fatal("signatureElements.verify() expected error")
	}
}

func TestSignatureElementsVerify_InvalidHex(t *testing.T) {
	e := signatureElements{verifier: &stubVerifier{valid: true}}

	_, err := e.verify("not-hex")
	if err == nil {
		t.Fatal("signatureElements.verify() expected error for invalid hex")
	}
}

func TestChain_ExecutesMiddlewaresInOrder(t *testing.T) {
	order := make([]string, 0, 5)

	base := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		order = append(order, "handler")
		w.WriteHeader(stdhttp.StatusNoContent)
	})

	mw := func(name string) func(stdhttp.Handler) stdhttp.Handler {
		return func(next stdhttp.Handler) stdhttp.Handler {
			return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				order = append(order, name+"-before")
				next.ServeHTTP(w, r)
				order = append(order, name+"-after")
			})
		}
	}

	h := chain(base, mw("one"), mw("two"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(stdhttp.MethodGet, "/", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusNoContent)
	}

	got := strings.Join(order, ",")
	want := "one-before,two-before,handler,two-after,one-after"
	if got != want {
		t.Fatalf("middleware order = %q, want %q", got, want)
	}
}
