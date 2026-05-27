package ressrf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/timescale/ressrf/go/ressrf/ressrftest"
)

func TestHTTPTransportBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	client := p.HTTPClient(nil)

	resp, err := client.Get("http://10.0.0.1/secret")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected blocked error, got nil")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPTransportBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	client := p.HTTPClient(nil)

	resp, err := client.Get("http://127.0.0.1:9090/admin")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected blocked error, got nil")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPClientRedirectToPrivateBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.168.1.1/internal", http.StatusFound)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	client := p.HTTPClient(nil)

	resp, err := client.Get(server.URL + "/start")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error on redirect to private IP, got nil")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestCheckRedirectBlocksHTTPSDowngrade(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	httpsReq, _ := http.NewRequest("GET", "https://example.com/start", http.NoBody)
	httpReq, _ := http.NewRequest("GET", "http://example.com/downgraded", http.NoBody)

	err := p.checkRedirect(httpReq, []*http.Request{httpsReq})
	if err == nil {
		t.Fatal("expected HTTPS to HTTP downgrade to be blocked")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPTransportAllowsPublicServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	ressrftest.DisableForTests(t)

	client := p.HTTPClient(nil)
	resp, err := client.Get(server.URL + "/ok")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClientTooManyRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	ressrftest.DisableForTests(t)

	client := &http.Client{
		Transport: p.HTTPTransport(nil),
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(server.URL + "/loop")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected too many redirects error")
	}
}
