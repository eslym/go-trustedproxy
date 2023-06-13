package trustedproxy

import (
	"fmt"
	"net"
)

// IPExtractor is an interface that extracts the ip address from the ip chain
type IPExtractor interface {
	// Resolve returns the proxy ip, trusted remote ip, and the rest of the ip chain
	Resolve(remote net.IP, forwarded []net.IP) (net.IP, net.IP, []net.IP, error)
}

// CIDRWhitelist check the ip from the right to the left, treat the first non-whitelisted ip as the remote ip,
// the ip before the remote as proxy ip, and the rest of the ip chain as the forwarded ips
// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#selecting_an_ip_address
type CIDRWhitelist struct {
	whitelist []*net.IPNet
}

// OffsetIPExtractor start from the right to the left, treat the first ip as the proxy ip, the second ip as
// the remote ip, and the rest of the ip chain as the forwarded ips
type OffsetIPExtractor uint

func (c *CIDRWhitelist) Resolve(remote net.IP, forwarded []net.IP) (net.IP, net.IP, []net.IP, error) {
	var proxy net.IP
	for len(forwarded) > 0 {
		if !c.Contains(remote) {
			break
		}
		proxy = remote
		remote, forwarded = pop(forwarded)
	}
	return proxy, remote, forwarded, nil
}

func (c *CIDRWhitelist) Contains(ip net.IP) bool {
	for _, cidr := range c.whitelist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (o OffsetIPExtractor) Resolve(remote net.IP, forwarded []net.IP) (net.IP, net.IP, []net.IP, error) {
	ips := append([]net.IP{}, forwarded...)
	ips = append(ips, remote)
	size := len(ips)
	if size <= int(o) {
		return nil, nil, nil, fmt.Errorf("mis-configured proxy chain")
	}
	proxy := ips[size-int(o)-1]
	remote = ips[size-int(o)-2]
	forwarded = ips[:size-int(o)-2]
	return proxy, remote, forwarded, nil
}

func pop(s []net.IP) (net.IP, []net.IP) {
	length := len(s)
	if length == 0 {
		return nil, s
	}
	return s[length-1], s[:length-1]
}
