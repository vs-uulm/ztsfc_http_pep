package proxies

import (
	"crypto/tls"
	"net/http"

	env "local.com/leobrada/ztsfc_http_pep/env"
)

var (
	Pdp_client_pool       []*http.Client
	Sfp_logic_client_pool []*http.Client
)

// The function NewClientPool prepares numerous TLS clients for connection with
// a specific service. The parameter poolSize defines the number of clients;
// certShownByPEP specifies the certificate which to use to authenticate
// against the requested service. Returned is the pool in form of a slice of
// http.Client instances.
func NewClientPool(poolSize int, certShownByPEP tls.Certificate) []*http.Client {
	client_pool := make([]*http.Client, poolSize)

	for i := 0; i < poolSize; i++ {
		pdp_client := new(http.Client)
		pdp_client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{certShownByPEP},
				InsecureSkipVerify: true,
				ClientAuth:         tls.RequireAndVerifyClientCert,
				ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
			},
		}
		client_pool[i] = pdp_client
	}

	return client_pool
}
