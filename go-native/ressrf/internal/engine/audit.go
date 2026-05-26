package engine

// AuditKind enumerates the lifecycle events the engine emits. The kind string
// is what bubbles up to the public AuditEvent.Kind field.
type AuditKind string

const (
	// AuditPolicyCreated fires once per Build() with the policy's preset,
	// cloud modules, and deny/allow counts.
	AuditPolicyCreated AuditKind = "policy_created"
	// AuditURLValidated fires for every IsRequestAllowed call with the URL,
	// the parsed scheme + host, and an `allowed` flag.
	AuditURLValidated AuditKind = "url_validated"
	// AuditHostValidated fires for every IsNetworkAllowed call with the
	// list of resolved IPs and an `allowed` flag.
	AuditHostValidated AuditKind = "host_validated"
)

// AuditEvent carries the kind plus arbitrary key/value fields. The public
// audit.AuditEvent serializes Fields to JSON so callers can attach arbitrary
// data without coupling the engine to a logging library.
type AuditEvent struct {
	Kind   AuditKind
	Fields map[string]any
}

// AuditSink is implemented by callers who want to receive audit events. The
// public ressrf.AuditSink type is the user-facing equivalent; the policy
// translates between the two so the engine stays free of public-API imports.
type AuditSink interface {
	Emit(event AuditEvent)
}
