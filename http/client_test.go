package http

import (
	"bytes"
	"errors"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ukashazia/anvil"
)

type recordingSigner struct {
	msg []byte
	sig []byte
	err error
}

func (s *recordingSigner) Sign(msg []byte) ([]byte, error) {
	s.msg = append([]byte(nil), msg...)
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.sig...), nil
}

func (s *recordingSigner) Algorithm() anvil.Algorithm {
	return anvil.Hmac
}

type readErrBody struct{}

func (b *readErrBody) Read(_ []byte) (int, error) {
	return 0, errors.New("read body error")
}

func (b *readErrBody) Close() error {
	return nil
}

type closeErrBody struct {
	r *bytes.Reader
}

func (b *closeErrBody) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *closeErrBody) Close() error {
	return errors.New("close body error")
}

func TestWithHmacSigner_ConfiguresHmacSigner(t *testing.T) {
	c := NewClient("client-1", WithHmacSigner("secret"))

	if c.cfg.signer == nil {
		t.Fatal("WithHmacSigner() should set signer")
	}

	if got := c.cfg.signer.Algorithm(); got != anvil.Hmac {
		t.Fatalf("WithHmacSigner() signer algorithm = %v, want %v", got, anvil.Hmac)
	}
}

func TestClientSign_SetsHeadersAndPreservesBody(t *testing.T) {
	body := "hello world"
	signer := &recordingSigner{sig: []byte{0xde, 0xad, 0xbe, 0xef}}
	c := &client{
		id:  "client-1",
		cfg: config{signer: signer},
	}

	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString(body))

	signed := c.Sign(req)
	if signed == nil {
		t.Fatal("Sign() returned nil")
	}

	nonce := signed.Header.Get(headerNonce)
	if nonce == "" {
		t.Fatal("Sign() missing nonce header")
	}

	reqTime := signed.Header.Get(headerReqTime)
	if reqTime == "" {
		t.Fatal("Sign() missing request time header")
	}
	if _, err := strconv.Atoi(reqTime); err != nil {
		t.Fatalf("Sign() request time is not numeric: %v", err)
	}

	if got := signed.Header.Get(headerClientId); got != "client-1" {
		t.Fatalf("Sign() client id = %q, want %q", got, "client-1")
	}

	if got := signed.Header.Get(headerReqSig); got != "deadbeef" {
		t.Fatalf("Sign() signature header = %q, want %q", got, "deadbeef")
	}

	gotBody, err := io.ReadAll(signed.Body)
	if err != nil {
		t.Fatalf("ReadAll(signed.Body) error = %v", err)
	}
	if string(gotBody) != body {
		t.Fatalf("Sign() request body = %q, want %q", string(gotBody), body)
	}

	wantCanonical := append([]byte(nil), []byte(nonce)...)
	wantCanonical = append(wantCanonical, []byte(reqTime)...)
	wantCanonical = append(wantCanonical, []byte("client-1")...)
	wantCanonical = append(wantCanonical, []byte(body)...)
	if !bytes.Equal(signer.msg, wantCanonical) {
		t.Fatalf("Sign() canonical message mismatch")
	}
}

func TestClientSign_ReturnsNilOnBodyReadError(t *testing.T) {
	c := &client{
		id:  "client-1",
		cfg: config{signer: &recordingSigner{sig: []byte{1}}},
	}

	req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
	req.Body = &readErrBody{}

	if got := c.Sign(req); got != nil {
		t.Fatal("Sign() should return nil when request body read fails")
	}
}

func TestClientSign_ReturnsNilOnBodyCloseError(t *testing.T) {
	c := &client{
		id:  "client-1",
		cfg: config{signer: &recordingSigner{sig: []byte{1}}},
	}

	req := httptest.NewRequest(stdhttp.MethodPost, "/", nil)
	req.Body = &closeErrBody{r: bytes.NewReader([]byte("payload"))}

	if got := c.Sign(req); got != nil {
		t.Fatal("Sign() should return nil when request body close fails")
	}
}

func TestClientSign_ReturnsNilOnSignerError(t *testing.T) {
	c := &client{
		id:  "client-1",
		cfg: config{signer: &recordingSigner{err: errors.New("sign failed")}},
	}

	req := httptest.NewRequest(stdhttp.MethodPost, "/", bytes.NewBufferString("payload"))

	if got := c.Sign(req); got != nil {
		t.Fatal("Sign() should return nil when signer returns an error")
	}
}

func TestSignatureElementsSign_BuildsCanonicalMessage(t *testing.T) {
	signer := &recordingSigner{sig: []byte{1, 2, 3}}
	e := signatureElements{
		nonce:    "nonce",
		t:        "time",
		clientId: "client",
		body:     []byte("body"),
		signer:   signer,
	}

	sig, err := e.sign()
	if err != nil {
		t.Fatalf("signatureElements.sign() error = %v", err)
	}

	if !bytes.Equal(sig, []byte{1, 2, 3}) {
		t.Fatalf("signatureElements.sign() signature = %v, want %v", sig, []byte{1, 2, 3})
	}

	if got, want := string(signer.msg), "noncetimeclientbody"; got != want {
		t.Fatalf("signatureElements.sign() canonical message = %q, want %q", got, want)
	}
}

func TestSignatureElementsSign_PropagatesSignerError(t *testing.T) {
	e := signatureElements{
		nonce:    "n",
		t:        "t",
		clientId: "c",
		body:     []byte("b"),
		signer:   &recordingSigner{err: errors.New("sign failed")},
	}

	_, err := e.sign()
	if err == nil {
		t.Fatal("signatureElements.sign() expected error")
	}
}
