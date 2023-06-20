package trustedproxy

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ForwardedRequest is an interface that extends http.Request with methods to
// access the trusted proxy information.
type ForwardedRequest interface {
	// GetOriginalRequest returns the original request.
	GetOriginalRequest() *http.Request

	// IsBehindProxy returns true if the request is coming from a trusted proxy.
	IsBehindProxy() bool

	// GetProxyIP returns the IP address of the trusted proxy.
	// nil is returned if the request is not coming from a trusted proxy.
	GetProxyIP() net.IP

	// GetTrustedHost returns the trusted host of the request.
	GetTrustedHost() string

	// GetTrustedProto returns the trusted protocol of the request.
	GetTrustedProto() string

	// GetTrustedRemoteAddr returns the trusted remote address of the request.
	GetTrustedRemoteAddr() net.IP

	// GetTrustedForwardedFor returns the trusted forwarded for of the request.
	GetTrustedForwardedFor() []net.IP

	// GetTrustedURL returns the trusted URL of the request.
	GetTrustedURL() *url.URL

	// GetTrustedRequest returns the trusted request of the request.
	GetTrustedRequest() *http.Request

	// BuildRequestForForward returns a copy of the request with proper X-Forwarded-* headers
	// set for forwarding to the next server.
	// stripForwardedIPs will keep the only trusted remote address in X-Forwarded-For.
	BuildRequestForForward(stripForwardedIPs bool) *http.Request
}

type forwardedRequest struct {
	*http.Request

	proxyIP net.IP

	trustedHost  string
	trustedProto string

	trustedRemoteAddr   net.IP
	trustedForwardedFor []net.IP

	trustedURL *url.URL

	trustedRequest *http.Request
}

func (f *forwardedRequest) GetOriginalRequest() *http.Request {
	return f.Request
}

func (f *forwardedRequest) IsBehindProxy() bool {
	return f.proxyIP != nil
}

func (f *forwardedRequest) GetProxyIP() net.IP {
	return f.proxyIP
}

func (f *forwardedRequest) GetTrustedHost() string {
	if f.trustedHost != "" {
		return f.trustedHost
	}
	if f.proxyIP == nil {
		f.trustedHost = f.Host
		return f.trustedHost
	}
	xHost := f.Header.Get("X-Forwarded-Host")
	if xHost != "" {
		f.trustedHost = xHost
		return f.trustedHost
	}
	f.trustedHost = f.Host
	return f.trustedHost
}

func (f *forwardedRequest) GetTrustedProto() string {
	if f.trustedProto != "" {
		return f.trustedProto
	}
	if f.proxyIP == nil {
		if f.TLS != nil {
			f.trustedProto = "https"
		} else {
			f.trustedProto = "http"
		}
		return f.trustedProto
	}
	xProto := f.Header.Get("X-Forwarded-Proto")

	// some proxy will pass "ws" or "wss" as X-Forwarded-Proto which is not a standard value,
	// so we will convert it to "http" or "https" respectively, any other value will be ignored.
	// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto
	switch strings.ToLower(xProto) {
	case "http", "ws":
		f.trustedProto = "http"
		return f.trustedProto
	case "https", "wss":
		f.trustedProto = "https"
		return f.trustedProto
	}
	if f.TLS != nil {
		f.trustedProto = "https"
	} else {
		f.trustedProto = "http"
	}
	return f.trustedProto
}

func (f *forwardedRequest) GetTrustedRemoteAddr() net.IP {
	return f.trustedRemoteAddr
}

func (f *forwardedRequest) GetTrustedForwardedFor() []net.IP {
	return f.trustedForwardedFor
}

func (f *forwardedRequest) GetTrustedURL() *url.URL {
	if f.trustedURL != nil {
		return f.trustedURL
	}
	u, _ := url.Parse(f.URL.String())
	u.Host = f.GetTrustedHost()
	u.Scheme = f.GetTrustedProto()
	f.trustedURL = u
	return f.trustedURL
}

func (f *forwardedRequest) GetTrustedRequest() *http.Request {
	if f.trustedRequest != nil {
		return f.trustedRequest
	}
	f.trustedRequest = f.Request.Clone(f.Context())
	f.trustedRequest.Host = f.GetTrustedHost()
	f.trustedRequest.URL = f.GetTrustedURL()
	f.trustedRequest.RemoteAddr = f.GetTrustedRemoteAddr().String()

	if len(f.trustedForwardedFor) > 0 {
		f.trustedRequest.Header.Set("X-Forwarded-For", f.trustedForwardedFor[0].String())
	} else {
		f.trustedRequest.Header.Del("X-Forwarded-For")
		f.trustedRequest.Header.Del("X-Forwarded-Host")
		f.trustedRequest.Header.Del("X-Forwarded-Proto")
	}

	return f.trustedRequest
}

func (f *forwardedRequest) BuildRequestForForward(stripForwardedIPs bool) *http.Request {
	req := f.Clone(f.Context())
	req.Host = f.GetTrustedHost()
	req.URL = f.GetTrustedURL()

	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Del("X-Real-IP")

	var ips []string

	if !stripForwardedIPs {
		for _, ip := range f.GetTrustedForwardedFor() {
			ips = append(ips, ip.String())
		}
	}

	ips = append(ips, f.GetTrustedRemoteAddr().String())

	req.Header.Set("X-Forwarded-For", strings.Join(ips, ", "))
	req.Header.Set("X-Forwarded-Host", f.GetTrustedHost())
	req.Header.Set("X-Forwarded-Proto", f.GetTrustedProto())

	return req
}
