package basic_auth

import "net/http"

func performX509auth(req *http.Request) bool {
	// Check if a verified client certificate is present
	return len(req.TLS.VerifiedChains) > 0
}
