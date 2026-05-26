// Package dialurl synthesises an HTTPS URL from a host that the URI validator
// can run its URL-level checks against, even when no real URL is available
// (e.g. at TCP dial time or in the SSH adapter). Shared by httpx and sshx so
// the IPv6 bracketing rule lives in exactly one place.
package dialurl

import (
	"fmt"
	"net"
)

// URLForHost returns "https://[host]" if host parses as an IPv6 address, or
// "https://host" otherwise.
func URLForHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("https://[%s]", host)
	}
	return fmt.Sprintf("https://%s", host)
}
