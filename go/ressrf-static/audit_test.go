package ressrfstatic

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// auditCase mirrors test_cases[] in audit_events.json. The shapes differ
// per action; we use map[string]any for the config and pull fields out per
// action handler.
type auditCase struct {
	Name          string         `json:"name"`
	Action        string         `json:"action"`
	Config        map[string]any `json:"config"`
	ExpectedEvent *expectedEvent `json:"expected_event"`
	Note          string         `json:"note,omitempty"`
}

type expectedEvent struct {
	Variant string         `json:"variant"`
	Fields  map[string]any `json:"fields"`
}

// auditVectorFile diverges from the standard `cases` shape used by other
// vector files — the audit JSON uses `test_cases`.
type auditVectorFile struct {
	Description string      `json:"description"`
	TestCases   []auditCase `json:"test_cases"`
}

func TestAuditEventVectors(t *testing.T) {
	var f auditVectorFile
	if err := json.Unmarshal(auditEventsJSON, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, c := range f.TestCases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			runAuditCase(t, c)
		})
	}
}

func runAuditCase(t *testing.T, c auditCase) {
	preset := parsePreset(t, getString(c.Config, "preset"))

	// Special case: `no_event_when_no_sink` — build without sink, expect no events.
	if c.Action == "create_policy" {
		if rawSink, ok := c.Config["audit_sink"]; ok && rawSink == nil {
			if _, err := NewPolicyBuilder(preset).Build(); err != nil {
				t.Fatalf("build: %v", err)
			}
			// No sink means no Emit calls happened; assert by construction.
			if c.ExpectedEvent != nil {
				t.Errorf("vector expected no event but defined an expected_event")
			}
			return
		}
	}

	sink := &RecordingSink{}
	b := NewPolicyBuilder(preset).WithAuditSink(sink)
	if mods, ok := c.Config["cloud_modules"].([]any); ok {
		for _, m := range mods {
			b.WithCloudModule(cloudModuleByName(t, m.(string)))
		}
	}

	switch c.Action {
	case "create_policy":
		if _, err := b.Build(); err != nil {
			t.Fatalf("build: %v", err)
		}
		// PolicyCreated emitted at build time.

	case "validate_host":
		p, err := b.Build()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		sink.Reset() // drop PolicyCreated; focus on the action under test
		host := getString(c.Config, "host")
		ips := getStringSlice(c.Config, "resolved_ips")
		_ = p.ValidateHost(host, ips)

	case "validate_url":
		p, err := b.Build()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		sink.Reset()
		_ = p.IsAllowed(context.Background(), getString(c.Config, "url"))

	case "connection_attempt", "redirect_intercepted":
		t.Skipf("action %q is exercised by Tasks 9-11 (protocol adapters)", c.Action)
		return

	default:
		t.Fatalf("unknown action %q", c.Action)
	}

	if c.ExpectedEvent == nil {
		if len(sink.Events) > 0 {
			t.Errorf("expected no event, got %d", len(sink.Events))
		}
		return
	}

	// Find the first event whose kind matches the expected variant.
	wantKind := variantToEventKind(c.ExpectedEvent.Variant)
	var got AuditEvent
	for _, e := range sink.Events {
		if e.EventKind() == wantKind {
			got = e
			break
		}
	}
	if got == nil {
		t.Fatalf("no event of kind %q (variant %q) in %d emitted events",
			wantKind, c.ExpectedEvent.Variant, len(sink.Events))
	}
	assertEventFields(t, got, c.ExpectedEvent.Fields)
}

// variantToEventKind maps the JSON variant name to the EventKind() string.
func variantToEventKind(variant string) string {
	switch variant {
	case "PolicyCreated":
		return "policy_created"
	case "HostValidated":
		return "host_validated"
	case "UrlValidated", "URLValidated":
		return "url_validated"
	case "ConnectionAttempt":
		return "connection_attempt"
	case "RedirectIntercepted":
		return "redirect_intercepted"
	}
	return ""
}

// assertEventFields checks each expected field against the event. Supports
// the special suffixes used in audit_events.json: _contains and _min.
func assertEventFields(t *testing.T, e AuditEvent, want map[string]any) {
	t.Helper()
	for k, v := range want {
		switch {
		case strings.HasSuffix(k, "_min"):
			real := strings.TrimSuffix(k, "_min")
			got := fieldInt(e, real)
			min := int(v.(float64))
			if got < min {
				t.Errorf("field %s = %d, want >= %d", real, got, min)
			}
		case strings.HasSuffix(k, "_contains"):
			real := strings.TrimSuffix(k, "_contains")
			got := fieldString(e, real)
			needle := v.(string)
			if !strings.Contains(got, needle) {
				t.Errorf("field %s = %q, want it to contain %q", real, got, needle)
			}
		default:
			assertField(t, e, k, v)
		}
	}
}

func assertField(t *testing.T, e AuditEvent, name string, want any) {
	t.Helper()
	switch ev := e.(type) {
	case *PolicyCreated:
		switch name {
		case "preset":
			if ev.Preset != want.(string) {
				t.Errorf("preset = %q, want %q", ev.Preset, want)
			}
		case "cloud_modules":
			wantList := toStringSlice(want)
			if !equalStringSlices(ev.CloudModules, wantList) {
				t.Errorf("cloud_modules = %v, want %v", ev.CloudModules, wantList)
			}
		case "deny_count":
			if int(want.(float64)) != ev.DenyCount {
				t.Errorf("deny_count = %d, want %d", ev.DenyCount, int(want.(float64)))
			}
		case "allow_count":
			if int(want.(float64)) != ev.AllowCount {
				t.Errorf("allow_count = %d, want %d", ev.AllowCount, int(want.(float64)))
			}
		}
	case *HostValidated:
		switch name {
		case "host":
			if ev.Host != want.(string) {
				t.Errorf("host = %q, want %q", ev.Host, want)
			}
		case "allowed":
			if ev.Allowed != want.(bool) {
				t.Errorf("allowed = %v, want %v", ev.Allowed, want)
			}
		}
	case *URLValidated:
		switch name {
		case "url":
			if ev.URL != want.(string) {
				t.Errorf("url = %q, want %q", ev.URL, want)
			}
		case "host":
			if ev.Host != want.(string) {
				t.Errorf("host = %q, want %q", ev.Host, want)
			}
		case "scheme":
			if ev.Scheme != want.(string) {
				t.Errorf("scheme = %q, want %q", ev.Scheme, want)
			}
		case "allowed":
			if ev.Allowed != want.(bool) {
				t.Errorf("allowed = %v, want %v", ev.Allowed, want)
			}
		}
	}
}

// fieldInt / fieldString extract specific fields by name across event types.
// Used by the _min/_contains assertions.
func fieldInt(e AuditEvent, name string) int {
	switch ev := e.(type) {
	case *PolicyCreated:
		switch name {
		case "deny_count":
			return ev.DenyCount
		case "allow_count":
			return ev.AllowCount
		}
	}
	return 0
}

func fieldString(e AuditEvent, name string) string {
	switch ev := e.(type) {
	case *HostValidated:
		switch name {
		case "host":
			return ev.Host
		case "reason":
			return ev.Reason
		case "match_reason":
			return ev.MatchReason
		}
	case *URLValidated:
		switch name {
		case "url":
			return ev.URL
		case "host":
			return ev.Host
		case "match_reason":
			return ev.MatchReason
		}
	}
	return ""
}

// --- small helpers ---

func getString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringSlice(m map[string]any, k string) []string {
	v, ok := m[k]
	if !ok {
		return nil
	}
	xs, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toStringSlice(v any) []string {
	xs, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.(string))
	}
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
