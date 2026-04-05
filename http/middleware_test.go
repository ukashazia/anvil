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
	err      error
	marked   []string
	pruneErr error
}

func (s *stubNonceStore) Mark(nonce string) error {
	s.marked = append(s.marked, nonce)
	return s.err
}

func (s *stubNonceStore) Prune() error {
	return s.pruneErr
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

func newValidSignedRequest(t *testing.T, body string, clientID string, secret string) *stdhttp.Request {
	t.Helper()

	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString(body))
	c := NewClient(clientID, WithHmacSigner(secret))
	signed := c.Sign(req)
	if signed == nil {
		t.Fatal("Sign() returned nil for valid request")
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
	req.Header.Set(headerClientId, "client-1")
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
			name: "missing verifier",
			opts: []middlewareConfig{
				WithNonceStore(&stubNonceStore{}),
			},
			wantErr: "verifier is required",
		},
		{
			name: "missing nonce store",
			opts: []middlewareConfig{
				WithHmacVerifier("secret"),
			},
			wantErr: "nonce store is required",
		},
		{
			name: "missing signer",
			opts: []middlewareConfig{
				WithHmacVerifier("secret"),
				WithNonceStore(&stubNonceStore{}),
			},
			wantErr: "signer is required",
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
		WithHmacVerifier("secret"),
		WithNonceStore(&stubNonceStore{}),
		func(m *middleware) { m.cfg.signer = &stubSigner{} },
		WithTtl(5*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	if m.ttl != 5*time.Second {
		t.Fatalf("middleware ttl = %v, want %v", m.ttl, 5*time.Second)
	}
}

func TestWithHmacVerifier_ConfiguresVerifier(t *testing.T) {
	m := &middleware{}
	WithHmacVerifier("secret")(m)

	if m.cfg.verifier == nil {
		t.Fatal("WithHmacVerifier() should set verifier")
	}

	if got := m.cfg.verifier.Algorithm(); got != anvil.Hmac {
		t.Fatalf("WithHmacVerifier() algorithm = %v, want %v", got, anvil.Hmac)
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

func TestMiddlewareVerify_AllValid_CallsHandler(t *testing.T) {
	secret := "my-secret"
	m, err := NewMiddleware(
		WithHmacVerifier(secret),
		func(m *middleware) { m.cfg.signer = &stubSigner{} },
		WithNonceStore(anvil.NewNonceStore(time.Minute)),
		WithTtl(10*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}

	req := newValidSignedRequest(t, "payload", "client-1", secret)

	called := false
	handler := m.Verify(newSuccessfulHandler(&called), nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusNoContent)
	}
	if !called {
		t.Fatal("handler should have been called")
	}
}

func TestValidateNonce_UnauthorizedOnDuplicateNonce(t *testing.T) {
	m := &middleware{
		cfg: config{nonceStore: &stubNonceStore{err: anvil.NonceExists}},
	}

	req := httptest.NewRequest(stdhttp.MethodGet, "/", nil)
	req.Header.Set(headerNonce, "n-1")

	called := false
	handler := m.validateNonce(newSuccessfulHandler(&called))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusUnauthorized)
	}
	if called {
		t.Fatal("next handler should not be called")
	}
}

func TestValidateNonce_InternalServerErrorOnStoreError(t *testing.T) {
	m := &middleware{
		cfg: config{nonceStore: &stubNonceStore{err: errors.New("store down")}},
	}

	req := httptest.NewRequest(stdhttp.MethodGet, "/", nil)
	req.Header.Set(headerNonce, "n-1")

	called := false
	handler := m.validateNonce(newSuccessfulHandler(&called))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != stdhttp.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, stdhttp.StatusInternalServerError)
	}
	if called {
		t.Fatal("next handler should not be called")
	}
}

func TestValidateTimeout(t *testing.T) {
	tests := []struct {
		name       string
		ttl        time.Duration
		reqTime    string
		wantStatus int
		wantCalled bool
	}{
		{
			name:       "bad header",
			ttl:        time.Second,
			reqTime:    "not-a-number",
			wantStatus: stdhttp.StatusInternalServerError,
			wantCalled: false,
		},
		{
			name:       "expired request",
			ttl:        10 * time.Millisecond,
			reqTime:    strconv.FormatInt(time.Now().Add(-2*time.Second).UnixMilli(), 10),
			wantStatus: stdhttp.StatusRequestTimeout,
			wantCalled: false,
		},
		{
			name:       "request within ttl",
			ttl:        10 * time.Second,
			reqTime:    strconv.FormatInt(time.Now().UnixMilli(), 10),
			wantStatus: stdhttp.StatusNoContent,
			wantCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &middleware{ttl: tt.ttl}
			req := httptest.NewRequest(stdhttp.MethodGet, "/", nil)
			req.Header.Set(headerReqTime, tt.reqTime)

			called := false
			handler := m.validateTimeout(newSuccessfulHandler(&called))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if called != tt.wantCalled {
				t.Fatalf("next called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

func TestValidateSignature_ErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		verifier    *stubVerifier
		buildReq    func() *stdhttp.Request
		wantStatus  int
		wantInvoked bool
	}{
		{
			name:        "missing signature",
			verifier:    &stubVerifier{valid: true},
			buildReq:    func() *stdhttp.Request { return newValidateSignatureRequest("payload", "") },
			wantStatus:  stdhttp.StatusUnauthorized,
			wantInvoked: false,
		},
		{
			name:        "invalid hex",
			verifier:    &stubVerifier{valid: true},
			buildReq:    func() *stdhttp.Request { return newValidateSignatureRequest("payload", "not-hex") },
			wantStatus:  stdhttp.StatusInternalServerError,
			wantInvoked: false,
		},
		{
			name:     "body read error",
			verifier: &stubVerifier{valid: true},
			buildReq: func() *stdhttp.Request {
				req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
				req.Body = &readErrRequestBody{}
				req.Header.Set(headerReqSig, "de")
				return req
			},
			wantStatus:  stdhttp.StatusInternalServerError,
			wantInvoked: false,
		},
		{
			name:     "body close error",
			verifier: &stubVerifier{valid: true},
			buildReq: func() *stdhttp.Request {
				req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
				req.Body = &closeErrRequestBody{r: bytes.NewReader([]byte("payload"))}
				req.Header.Set(headerReqSig, "de")
				return req
			},
			wantStatus:  stdhttp.StatusInternalServerError,
			wantInvoked: false,
		},
		{
			name:        "verifier error",
			verifier:    &stubVerifier{err: errors.New("verify error")},
			buildReq:    func() *stdhttp.Request { return newValidateSignatureRequest("payload", "de") },
			wantStatus:  stdhttp.StatusInternalServerError,
			wantInvoked: true,
		},
		{
			name:        "invalid signature",
			verifier:    &stubVerifier{valid: false},
			buildReq:    func() *stdhttp.Request { return newValidateSignatureRequest("payload", "de") },
			wantStatus:  stdhttp.StatusUnauthorized,
			wantInvoked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &middleware{cfg: config{verifier: tt.verifier}}
			req := tt.buildReq()

			called := false
			handler := m.validateSignature(newSuccessfulHandler(&called))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if called {
				t.Fatal("next handler should not be called")
			}
			if tt.verifier.invoked != tt.wantInvoked {
				t.Fatalf("verifier invoked = %v, want %v", tt.verifier.invoked, tt.wantInvoked)
			}
		})
	}
}

func TestValidateSignature_PassesCanonicalMessageAndRestoresBody(t *testing.T) {
	v := &stubVerifier{valid: true}
	m := &middleware{cfg: config{verifier: v}}

	body := "payload"
	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set(headerNonce, "nonce")
	req.Header.Set(headerReqTime, "123")
	req.Header.Set(headerClientId, "client")
	req.Header.Set(headerReqSig, "dead")

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

	if !v.invoked {
		t.Fatal("verifier should have been invoked")
	}

	if got, want := string(v.msg), "nonce123clientpayload"; got != want {
		t.Fatalf("verify canonical message = %q, want %q", got, want)
	}

	if got, want := v.sig, []byte{0xde, 0xad}; !bytes.Equal(got, want) {
		t.Fatalf("decoded signature = %v, want %v", got, want)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(req.Body) error = %v", err)
	}
	if string(restored) != body {
		t.Fatalf("request body after validateSignature = %q, want %q", string(restored), body)
	}
}

func TestSignatureElementsVerify_BuildsCanonicalMessage(t *testing.T) {
	v := &stubVerifier{valid: true}
	e := signatureElements{
		nonce:    "nonce",
		t:        "time",
		clientId: "client",
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
		clientId: "c",
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
