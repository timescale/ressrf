package ressrfstatic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// redirectChainCase mirrors test_cases[] in redirect_chains.json.
type redirectChainCase struct {
	Name               string   `json:"name"`
	Chain              []string `json:"chain"`
	PolicyPreset       string   `json:"policy_preset"`
	AllowCIDRs         []string `json:"allow_cidrs,omitempty"`
	AllowPlaintextHTTP bool     `json:"allow_plaintext_http,omitempty"`
	MaxRedirects       int      `json:"max_redirects,omitempty"`
	Expected           string   `json:"expected"` // "allowed" | "blocked"
	BlockedAtHop       int      `json:"blocked_at_hop,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	Note               string   `json:"note,omitempty"`
}

// defaultMaxRedirects matches the limit baked into Policy.checkRedirect.
const defaultMaxRedirects = 10

func TestRedirectChainVectors(t *testing.T) {
	var f struct {
		TestCases []redirectChainCase `json:"test_cases"`
	}
	require.NoError(t, json.Unmarshal(redirectChainsJSON, &f))

	for _, c := range f.TestCases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			p := buildRedirectPolicy(t, c)

			// Walk the chain hop-by-hop. The runner mirrors what
			// http.Client.CheckRedirect does: IsAllowed on the target plus
			// cross-hop checks (max-redirects, HTTPS→HTTP downgrade). It is
			// decoupled from a real HTTP server so we can exercise vectors
			// that point at literal metadata IPs.
			maxRedirects := c.MaxRedirects
			if maxRedirects == 0 {
				maxRedirects = defaultMaxRedirects
			}
			firstScheme, _, _ := parseURLComponents(c.Chain[0])
			firstScheme = strings.ToLower(firstScheme)

			ctx := context.Background()
			for hop, raw := range c.Chain {
				err := walkRedirectHop(ctx, p, c, hop, raw, firstScheme, maxRedirects)

				if c.Expected == "blocked" && hop == c.BlockedAtHop {
					require.Error(t, err, "hop %d (%s) should be blocked", hop, raw)
					return // chain stops at first block
				}
				require.NoError(t, err, "hop %d (%s) unexpectedly blocked", hop, raw)
			}
			require.NotEqual(t, "blocked", c.Expected, "chain passed but vector expected block at hop %d", c.BlockedAtHop)
		})
	}
}

// buildRedirectPolicy constructs the policy described by a vector case.
func buildRedirectPolicy(t *testing.T, c redirectChainCase) *Policy {
	t.Helper()
	b := NewPolicyBuilder(parsePreset(t, c.PolicyPreset))
	if len(c.AllowCIDRs) > 0 {
		b.WithAllowedCIDRs(c.AllowCIDRs...)
	}
	if c.AllowPlaintextHTTP {
		b.WithAllowPlaintextHTTP(true)
	}
	p, err := b.Build()
	require.NoError(t, err)
	return p
}

// walkRedirectHop runs IsAllowed on one hop and applies the cross-hop
// downgrade / max-redirect rules that http.Client.CheckRedirect normally
// owns. Returns nil if the hop is allowed end-to-end.
func walkRedirectHop(ctx context.Context, p *Policy, c redirectChainCase, hop int, raw, firstScheme string, maxRedirects int) error {
	if err := p.IsAllowed(ctx, raw); err != nil {
		return err
	}
	if hop == 0 {
		return nil
	}
	scheme, _, _ := parseURLComponents(raw)
	if hop >= maxRedirects {
		return &BlockedError{Reason: ReasonURLRuleDenied, URL: raw, DetailText: "too many redirects"}
	}
	if !c.AllowPlaintextHTTP && strings.ToLower(scheme) == "http" && firstScheme == "https" {
		return &BlockedError{Reason: ReasonURLRuleDenied, URL: raw, DetailText: "HTTPS to HTTP downgrade during redirect"}
	}
	return nil
}

func TestHTTPRoundTripBlocksPrivate(t *testing.T) {
	// httptest.Server binds to 127.0.0.1, which ExternalOnly denies.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	require.NoError(t, err)

	resp, err := p.HTTPClient(nil).Get(srv.URL)
	require.Error(t, err, "request to loopback test server should be blocked")
	require.ErrorIs(t, err, ErrBlocked)
	require.Nil(t, resp)
}

func TestHTTPCheckRedirectBlocksToIMDS(t *testing.T) {
	// External server with allow-127 override so the test can talk to itself;
	// the redirect target is the IMDS IP, which is denied.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8"). // allow connecting to the test server itself
		Build()
	require.NoError(t, err)

	resp, err := p.HTTPClient(nil).Get(srv.URL)
	require.Error(t, err, "redirect to IMDS should be blocked")
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	require.Contains(t, err.Error(), "ressrfstatic", "error should be sourced from ressrfstatic, got %v", err)
}

func TestHTTPRedirectEmitsRedirectIntercepted(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		WithAuditSink(sink).
		Build()
	require.NoError(t, err)

	resp, err := p.HTTPClient(nil).Get(srv.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	var found bool
	for _, e := range sink.Events {
		if _, ok := e.(*RedirectIntercepted); ok {
			found = true
			break
		}
	}
	require.True(t, found, "expected at least one RedirectIntercepted event, got %d total events", len(sink.Events))
}
