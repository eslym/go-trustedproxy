package trustedproxy

import (
	"net"
	"net/http"
	"strings"
)

type ErrorType uint

const (
	// ErrTypeUnknownRemoteAddr is returned when the remote address is not a valid IP address and port.
	ErrTypeUnknownRemoteAddr ErrorType = iota

	// ErrTypeIPExtractorError is returned when the IP extractor returns an error.
	ErrTypeIPExtractorError
)

// ErrorHandler is the function used to handle errors.
type ErrorHandler func(t ErrorType, err error, res http.ResponseWriter, req *http.Request)

// DefaultErrorHandler is the default error handler.
var DefaultErrorHandler ErrorHandler = func(_ ErrorType, err error, res http.ResponseWriter, req *http.Request) {
	http.Error(res, err.Error(), http.StatusInternalServerError)
}

// WithTrustedRequest is a middleware that modify the request to use the trusted proxy ip, remote ip, and forwarded ips
func WithTrustedRequest(resolver IPExtractor, next http.Handler) http.Handler {
	return &HTTPHandler{
		Extractor:    resolver,
		ErrorHandler: DefaultErrorHandler,
		Next:         next,
	}
}

// WithTrustedProxyContext is a middleware that set the context with the trusted proxy ip, remote ip, and forwarded ips
// use context.Value(CtxKeyForwardedRequest).(*forwardedRequest) to get the request with extended info
func WithTrustedProxyContext(resolver IPExtractor, next http.Handler) http.Handler {
	handler := &HTTPHandler{
		Extractor:    resolver,
		ErrorHandler: DefaultErrorHandler,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.SetTrustedProxyContext(w, r, next)
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
