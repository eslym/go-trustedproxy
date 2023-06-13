package trustedproxy

type contextKey struct {
	name string
}

var (
	// CtxKeyForwardedRequest is the context key for the forwarded request.
	CtxKeyForwardedRequest = &contextKey{"forwarded-request"}
)
