package proxies

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	env "local.com/leobrada/ztsfc_http_pep/env"
)

var (
	Basic_auth_proxy      *httputil.ReverseProxy
	Pdp_client_pool       []*http.Client
	Sfp_logic_client_pool []*http.Client
	Service_proxy         *httputil.ReverseProxy
)

func NewServiceProxy() *httputil.ReverseProxy {

	basic_auth_url, _ := url.Parse("https://10.5.0.53")
	proxy := httputil.NewSingleHostReverseProxy(basic_auth_url)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		TLSHandshakeTimeout: 0 * time.Millisecond,
		TLSClientConfig: &tls.Config{
			// TODO: Replace it by loading the cert for the first SF in the chain
			Certificates:           []tls.Certificate{env.Config.Sf_pool["dummy"].X509KeyPair_shown_by_pep_to_sf},
			InsecureSkipVerify:     true,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              env.Config.CA_cert_pool_pep_accepts_from_int,
			SessionTicketsDisabled: false,
		},
	}

	return proxy
}

func NewBasicAuthProxy() *httputil.ReverseProxy {

	basic_auth_url, _ := url.Parse("https://10.4.0.52")
	proxy := httputil.NewSingleHostReverseProxy(basic_auth_url)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		TLSHandshakeTimeout: 0 * time.Millisecond,
		TLSClientConfig: &tls.Config{
			// TODO: Replace it by loading the cert for the first SF in the chain
			Certificates:           []tls.Certificate{env.Config.Sf_pool["dummy"].X509KeyPair_shown_by_pep_to_sf},
			InsecureSkipVerify:     true,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              env.Config.CA_cert_pool_pep_accepts_from_int,
			SessionTicketsDisabled: false,
		},
	}

	return proxy
}

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
