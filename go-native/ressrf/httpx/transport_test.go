package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/httpx"
	"github.com/timescale/ressrf/go-native/ressrf/ressrftest"
)

func buildExternalPolicy(t *testing.T) *ressrf.Policy {
	t.Helper()
	p, err := ressrf.NewPolicy(ressrf.PresetExternalOnly,
		ressrf.WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHTTPTransportBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	client := httpx.Client(p)

	resp, err := client.Get("http://10.0.0.1/secret")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected blocked error, got nil")
	}
	if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPTransportBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	client := httpx.Client(p)

	resp, err := client.Get("http://127.0.0.1:9090/admin")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected blocked error, got nil")
	}
	if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPClientRedirectToPrivateBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.168.1.1/internal", http.StatusFound)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	client := httpx.Client(p)

	resp, err := client.Get(server.URL + "/start")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error on redirect to private IP, got nil")
	}
	if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestCheckRedirectBlocksHTTPSDowngrade(t *testing.T) {
	p := buildExternalPolicy(t)

	httpsReq, _ := http.NewRequest("GET", "https://example.com/start", http.NoBody)
	httpReq, _ := http.NewRequest("GET", "http://example.com/downgraded", http.NoBody)

	err := httpx.CheckRedirect(p)(httpReq, []*http.Request{httpsReq})
	if err == nil {
		t.Fatal("expected HTTPS to HTTP downgrade to be blocked")
	}
	if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestHTTPTransportAllowsPublicServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	ressrftest.DisableForTests(t)

	client := httpx.Client(p)
	resp, err := client.Get(server.URL + "/ok")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// Custom RoundTrippers (mocks, middleware chains) must be preserved by
// Transport, not silently replaced with http.DefaultTransport.Clone().
// Such a base loses the dial-time IP recheck but keeps URL-level enforcement.
func TestTransportPreservesNonHTTPTransportBase(t *testing.T) {
	p := buildExternalPolicy(t)

	var called bool
	mock := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 204, Body: http.NoBody, Request: req}, nil
	})

	client := &http.Client{Transport: httpx.Transport(p, httpx.WithBaseTransport(mock))}
	resp, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	_ = resp.Body.Close()
	if !called {
		t.Fatal("custom RoundTripper was not invoked; Transport silently replaced it")
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHTTPClientTooManyRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer server.Close()

	p := buildExternalPolicy(t)
	ressrftest.DisableForTests(t)

	client := &http.Client{
		Transport: httpx.Transport(p),
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
