package auth

import (
	"net"
	"net/netip"
	"strings"

	"mspbroker/internal/config"
)

// ClientIP determines the client address for allowlist checks. The socket
// peer is used unless it is inside trusted, in which case X-Forwarded-For is
// walked right to left, skipping trusted proxies; the first address that is
// not a trusted proxy is the client. Entries further left are client-supplied
// and never believed over a nearer untrusted hop. If the header is absent or
// any entry on the way is unparseable, the peer address is used.
//
// The result is invalid (IsValid false) if the peer address cannot be parsed.
func ClientIP(remoteAddr string, xff []string, trusted []netip.Prefix) netip.Addr {
	peer := parseHostPort(remoteAddr)
	if !peer.IsValid() || len(xff) == 0 || !inAny(trusted, peer) {
		return peer
	}
	var hops []string
	for _, h := range xff {
		for _, part := range strings.Split(h, ",") {
			hops = append(hops, strings.TrimSpace(part))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			return peer // garbage in the chain: fall back to the socket peer
		}
		a = a.Unmap().WithZone("")
		if inAny(trusted, a) {
			if i == 0 {
				return a // every hop is a trusted proxy
			}
			continue
		}
		return a
	}
	return peer
}

func parseHostPort(s string) netip.Addr {
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

func inAny(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseAllowEntry validates one ip_allow entry (CIDR or bare address).
func ParseAllowEntry(s string) (netip.Prefix, error) { return config.ParsePrefix(s) }

// IPAllowed reports whether ip may use a key with the given allowlist. An
// empty list allows any address (including an unknown one). With a non-empty
// list, an invalid ip is denied, and entries that do not parse match nothing
// (fail closed).
func IPAllowed(allow []string, ip netip.Addr) bool {
	if len(allow) == 0 {
		return true
	}
	if !ip.IsValid() {
		return false
	}
	for _, e := range allow {
		p, err := ParseAllowEntry(e)
		if err != nil {
			continue
		}
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
