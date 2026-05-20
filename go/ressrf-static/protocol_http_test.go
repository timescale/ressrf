package ressrfstatic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// redirectChainCase mirrors test_cases[] in redirect_chains.json.
type redirectChainCase struct {
	Name              string   `json:"name"`
	Chain             []string `json:"chain"`
	PolicyPreset      string   `json:"policy_preset"`
	AllowCIDRs        []string `json:"allow_cidrs,omitempty"`
	AllowPlaintextHTTP bool    `json:"allow_plaintext_http,omitempty"` // not currently consulted
	MaxRedirects      int      `json:"max_redirects,omitempty"`
	Expected          string   `json:"expected"` // "allowed" | "blocked"
	BlockedAtHop      int      `json:"blocked_at_hop,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	Note              string   `json:"note,omitempty"`
}

func TestRedirectChainVectors(t *testing.T) {
	var f struct {
		TestCases []redirectChainCase `json:"test_cases"`
	}
	if err := json.Unmarshal(redirectChainsJSON, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.TestCases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			preset := parsePreset(t, c.PolicyPreset)
			b := NewPolicyBuilder(preset)
			if len(c.AllowCIDRs) > 0 {
				b.WithAllowedCIDRs(c.AllowCIDRs...)
			}
			if c.AllowPlaintextHTTP {
				b.WithAllowPlaintextHTTP(true)
			}
			p, err := b.Build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			// Walk the chain hop-by-hop and apply IsAllowed at each hop —
			// equivalent to what checkRedirect would do during a real
			// 3xx-followed request. Test runner is decoupled from any HTTP
			// server so we can exercise vectors that point at literal
			// metadata IPs which never get resolved.
			// Walk the chain hop-by-hop. The runner mirrors what
			// http.Client.CheckRedirect does: IsAllowed on the target +
			// cross-hop checks (max redirects, HTTPS-to-HTTP downgrade).
			ctx := context.Background()
			maxRedirects := c.MaxRedirects
			if maxRedirects == 0 {
				maxRedirects = 10
			}
			prevScheme := ""
			firstScheme := ""
			for hop, raw := range c.Chain {
				// Capture scheme cheaply (already lowercased in parseURLComponents).
				scheme, _, _ := parseURLComponents(raw)
				if hop == 0 {
					firstScheme = strings.ToLower(scheme)
				}

				err := p.IsAllowed(ctx, raw)
				// Cross-hop: max-redirects + downgrade.
				if err == nil && hop > 0 {
					if hop >= maxRedirects {
						err = &BlockedError{Reason: ReasonURLRuleDenied, URL: raw, DetailText: "too many redirects"}
					} else if !c.AllowPlaintextHTTP && strings.ToLower(scheme) == "http" && firstScheme == "https" {
						err = &BlockedError{Reason: ReasonURLRuleDenied, URL: raw, DetailText: "HTTPS to HTTP downgrade during redirect"}
					}
				}
				_ = prevScheme

				if c.Expected == "blocked" && hop == c.BlockedAtHop {
					if err == nil {
						t.Errorf("hop %d (%s) should be blocked, but was allowed", hop, raw)
					}
					return
				}
				if err != nil {
					t.Errorf("hop %d (%s) unexpectedly blocked: %v", hop, raw, err)
					return
				}
				prevScheme = scheme
			}
			if c.Expected == "blocked" {
				t.Errorf("expected blocked at hop %d but full chain passed", c.BlockedAtHop)
			}
		})
	}
}

// TestHTTPRoundTripBlocksPrivate covers the transport layer end-to-end.
func TestHTTPRoundTripBlocksPrivate(t *testing.T) {
	// httptest.Server binds to 127.0.0.1, which ExternalOnly denies.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatal(err)
	}
	c := p.HTTPClient(nil)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected request to be blocked, got %d", resp.StatusCode)
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("expected errors.Is(ErrBlocked), got %v", err)
	}
}

func TestHTTPCheckRedirectBlocksToIMDS(t *testing.T) {
	// External server with allow-127 override so the test can talk to
	// itself; the redirect target is the IMDS IP which is denied.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8"). // allow connecting to the test server
		Build()
	if err != nil {
		t.Fatal(err)
	}
	c := p.HTTPClient(nil)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected redirect to be blocked")
	}
	if !strings.Contains(err.Error(), "ressrfstatic") {
		t.Errorf("expected ressrfstatic error, got %v", err)
	}
}

func TestHTTPRedirectEmitsRedirectIntercepted(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Same-origin absolute redirect.
		http.Redirect(w, r, fmt.Sprintf("%s/next", srv.URL), http.StatusFound)
	}))
	defer srv.Close()

	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		WithAuditSink(sink).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	c := p.HTTPClient(nil)
	resp, _ := c.Get(srv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	// We don't care about the final status — checking that the redirect
	// was observed in the audit stream.
	found := false
	for _, e := range sink.Events {
		if _, ok := e.(*RedirectIntercepted); ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no RedirectIntercepted event emitted")
	}
}

