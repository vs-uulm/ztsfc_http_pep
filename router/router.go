package router

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	pdp "local.com/leobrada/ztsfc_http_pep/authorization"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	env "local.com/leobrada/ztsfc_http_pep/env"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	sfpl "local.com/leobrada/ztsfc_http_pep/sfp_logic"
)

type Router struct {
	tls_config *tls.Config
	frontend   *http.Server
	lw         *logwriter.LogWriter
}

func NewRouter() (*Router, error) {
	router := new(Router)
	router.lw = logwriter.LW

	router.tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           nil,
		//ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  env.Config.CA_cert_pool_pep_accepts_from_ext,
		GetCertificate: func(cli *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// load a suitable certificate that is shown to clients according the request domain/TLS SNI
			service, ok := env.Config.Service_SNI_map[cli.ServerName]
			if !ok {
				return nil, fmt.Errorf("Error: Could not serve a suitable certificate for %s\n", cli.ServerName)
			}
			return &service.X509KeyPair_shown_by_pep_to_client, nil
		},
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         env.Config.Pep.Listen_addr,
		TLSConfig:    router.tls_config,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(logwriter.LW, "", 0),
	}

	//http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 10000
	//http.DefaultTransport.(*http.Transport).TLSHandshakeTimeout = 0 * time.Second

	return router, nil
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Used for measuring the time ServeHTTP runs
	//start := time.Now()
	var err error
	md := new(metadata.Cp_metadata)

	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	logwriter.LW.LogHTTPRequest(req)

	// BASIC AUTHENTICATION
	// Check if the user is authenticated; if not authenticate her; if that fails return an error
	// TODO: return error to client?
	// Check if user has a valid session already
	if !bauth.User_sessions_is_valid(req, md) {
		if !bauth.Basic_auth(w, req) {
			//      fmt.Printf("Authentication,'%s', %v\n", md.SFC, time.Since(start))
			return
		}
	}

	// AUTHORIZATION
	err = pdp.PerformAuthorization(req, md)
	if err != nil {
		logwriter.LW.Logger.WithField("issuer", "PDP").Error(err)
		return
	}

	if !md.Auth_decision {
		logwriter.LW.Logger.Info("Request was rejected due to too low trust score")
		w.WriteHeader(503)
		return
	}
	logwriter.LW.Logger.Debugf("Request passed PDP. SFC: %s", md.SFC)

	// SFP LOGIC
	err = sfpl.TransformSFCintoSFP(md)
	if err != nil {
		logwriter.LW.Logger.WithField("issuer", "SFP Logic").Error(err)
		return
	}
	logwriter.LW.Logger.Debugf("Request passed SFP logic. SFP before joining with service url: %s", md.SFP)

	// If user could be authenticated, create ReverseProxy variable for the connection to serve
	var proxy *httputil.ReverseProxy
	var serviceURL *url.URL

	serviceConf, ok := env.Config.Service_SNI_map[md.Resource]
	if !ok {
		logwriter.LW.Logger.WithField("sni", md.Resource).Error("Requested SNI has no match in config file.")
		return
	}

	if len(md.SFP) == 0 {
		serviceURL, _ = url.Parse(serviceConf.Target_service_addr)
	} else {
		md.SFP = md.SFP + ", " + serviceConf.Target_service_addr
		sfp_slices := strings.Split(md.SFP, ",")
		next_hop := sfp_slices[0]
		logwriter.LW.Logger.Debugf("Next Hop: %s", next_hop)

		sfp_slices = sfp_slices[1:]
		if len(sfp_slices) != 0 {
			md.SFP = strings.Join(sfp_slices[:], ",")
			req.Header.Set("sfp", md.SFP)
		}
		serviceURL, err = url.Parse(next_hop)
		if err != nil {
			logwriter.LW.Logger.WithField("url", next_hop).Error("Could not parse URL for next hop")
			return
		}
	}
	logwriter.LW.Logger.Debugf("SFP after joining: %s", md.SFP)
	logwriter.LW.Logger.Debugf("Service URL: %s", serviceURL.String())

	proxy = httputil.NewSingleHostReverseProxy(serviceURL)

	proxy.ErrorLog = log.New(router.lw, "", 0)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			// TODO: Replace it by loading the cert for the first SF in the chain
			Certificates:       []tls.Certificate{env.Config.Sf_pool["dummy"].X509KeyPair_shown_by_pep_to_sf},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
		},
	}

	proxy.ServeHTTP(w, req)
	//proxies.Service_proxy.ServeHTTP(w, req)
	//  fmt.Printf("SFC: %s with exec time: %v\n", md.SFC, time.Since(start))
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
