package ressrfstatic

// AuditSink receives policy events emitted during evaluation. Implementations
// must be safe for concurrent use; a Policy may be shared across goroutines.
//
// Mirrors crates/ressrf-core/src/audit.rs::AuditSink. Pass an implementation
// to PolicyBuilder.WithAuditSink to enable emission.
type AuditSink interface {
	Emit(event AuditEvent)
}

// AuditEvent is the marker interface for all audit event types. Type-switch
// on the concrete type to inspect fields.
type AuditEvent interface {
	EventKind() string
}

// HostValidated fires when a host or set of resolved IPs is checked against
// the IP-level deny/allow sets.
type HostValidated struct {
	Host        string
	ResolvedIPs []string
	Allowed     bool
	Reason      string // empty when Allowed
}

func (*HostValidated) EventKind() string { return "host_validated" }

// URLValidated fires when a URL goes through the full IsAllowed pipeline.
type URLValidated struct {
	URL     string
	Scheme  string
	Host    string
	Allowed bool
	Reason  string // empty when Allowed
}

func (*URLValidated) EventKind() string { return "url_validated" }

// ConnectionAttempt fires from the TCP / HTTP / SSH adapters when a
// connection is about to be initiated.
type ConnectionAttempt struct {
	Protocol   string // "tcp" | "http" | "https" | "ssh"
	RemoteAddr string
	Allowed    bool
	Reason     string
}

func (*ConnectionAttempt) EventKind() string { return "connection_attempt" }

// RedirectIntercepted fires from the HTTP CheckRedirect hook.
type RedirectIntercepted struct {
	FromURL string
	ToURL   string
	Allowed bool
	Reason  string
}

func (*RedirectIntercepted) EventKind() string { return "redirect_intercepted" }

// PolicyCreated fires once at the end of PolicyBuilder.Build. Useful for
// recording the effective policy snapshot.
type PolicyCreated struct {
	Preset       string
	CloudModules []string
	AllowCount   int
	DenyCount    int
}

func (*PolicyCreated) EventKind() string { return "policy_created" }

// RecordingSink is a test helper that collects every emitted event in order.
// Safe for sequential test use; not goroutine-safe.
type RecordingSink struct {
	Events []AuditEvent
}

func (r *RecordingSink) Emit(e AuditEvent) {
	r.Events = append(r.Events, e)
}

// Reset drops all collected events. Useful for reusing a sink across
// sub-tests.
func (r *RecordingSink) Reset() {
	r.Events = r.Events[:0]
}
