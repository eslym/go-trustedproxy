package trustedproxy

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// WithTrustedRequest is a middleware that modify the request to use the trusted proxy ip, remote ip, and forwarded ips
func WithTrustedRequest(resolver IPExtractor, next http.Handler) http.Handler {
	return WithTrustedProxyContext(resolver, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr := r.Context().Value(CtxKeyForwardedRequest).(*forwardedRequest)
		next.ServeHTTP(w, fr.GetTrustedRequest())
	}))
}

// WithTrustedProxyContext is a middleware that set the context with the trusted proxy ip, remote ip, and forwarded ips
// use context.Value(CtxKeyForwardedRequest).(*forwardedRequest) to get the request with extended info
func WithTrustedProxyContext(resolver IPExtractor, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr := &forwardedRequest{
			Request: r,
		}
		r = r.Clone(context.WithValue(r.Context(), CtxKeyForwardedRequest, fr))
		ips := ExtractForwardedForIPs(&r.Header)
		proxy, trustedRemote, restIps, err := resolver.Resolve(net.ParseIP(r.RemoteAddr), ips)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fr.proxyIP = proxy
		fr.trustedRemoteAddr = trustedRemote
		fr.trustedForwardedFor = restIps
		next.ServeHTTP(w, r)
	})
}

// ExtractForwardedForIPs returns the ip chain from the X-Forwarded-For header
func ExtractForwardedForIPs(h *http.Header) []net.IP {
	var res []net.IP
	headers := h.Values("X-Forwarded-For")
	for _, header := range headers {
		for _, val := range strings.Split(header, ",") {
			ip := net.ParseIP(val)
			if ip == nil {
				continue
			}
			res = append(res, net.ParseIP(val))
		}
	}
	return res
}
