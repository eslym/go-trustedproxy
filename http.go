package trustedproxy

import (
	"context"
	"net"
	"net/http"
)

// HTTPHandler is a middleware that sets the trusted proxy context and alters the request to
// use the trusted proxy ip, remote ip, and forwarded ips.
type HTTPHandler struct {
	// Extractor is the IPExtractor used to determine the trusted proxy ip, remote ip, and forwarded ips.
	Extractor IPExtractor

	// ErrorHandler is the function used to handle errors.
	ErrorHandler ErrorHandler

	// Next is the next http.Handler in the middleware chain.
	Next http.Handler
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.SetTrustedProxyContext(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr := r.Context().Value(CtxKeyForwardedRequest).(*forwardedRequest)
		h.Next.ServeHTTP(w, fr.GetTrustedRequest())
	}))
}

func (h *HTTPHandler) SetTrustedProxyContext(w http.ResponseWriter, r *http.Request, next http.Handler) {
	fr := &forwardedRequest{}
	r = r.Clone(context.WithValue(r.Context(), CtxKeyForwardedRequest, fr))
	fr.Request = r
	ips := ExtractForwardedForIPs(&r.Header)
	raddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		DefaultErrorHandler(ErrTypeUnknownRemoteAddr, err, w, r)
		return
	}
	proxy, trustedRemote, restIps, err := h.Extractor.Resolve(raddr.IP, ips)
	if err != nil {
		DefaultErrorHandler(ErrTypeIPExtractorError, err, w, r)
		return
	}
	fr.proxyIP = proxy
	fr.trustedRemoteAddr = trustedRemote
	fr.trustedForwardedFor = restIps
	next.ServeHTTP(w, r)
}
