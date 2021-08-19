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
}

func NewRouter() (*Router, error) {
	router := new(Router)

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
		//ErrorLog:     log.New(logwriter.LW.Logger.WriterLevel(logrus.ErrorLevel), "", 0),
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

	// If user could be authenticated, create ReverseProxy variable for the connection to serve
	var proxy *httputil.ReverseProxy
	var serviceURL *url.URL
	var certShownByPEP tls.Certificate

	serviceConf, ok := env.Config.Service_SNI_map[md.Resource]
	if !ok {
		logwriter.LW.Logger.WithField("sni", md.Resource).Error("Requested SNI has no match in config file.")
		return
	}

	// SFP LOGIC

	// @author:marie
	// only connect to SFP logic, if SFC is not empty
	if len(md.SFC) == 0 {

		logwriter.LW.Logger.Debug("SFC is empty. Thus, no forwarding to SFP logic")
		serviceURL = serviceConf.Target_service_url
		certShownByPEP = serviceConf.X509KeyPair_shown_by_pep_to_service

	} else {

		err = sfpl.TransformSFCintoSFP(md)
		if err != nil {
			logwriter.LW.Logger.WithField("issuer", "SFP Logic").Error(err)
			return
		}
		logwriter.LW.Logger.Debugf("Request passed SFP logic. SFP before joining with service url: %s", md.SFP)

		if len(md.SFP) == 0 {
			logwriter.LW.Logger.Error("SFP is empty, even though SFC is not")
			return
		}

		// @author:marie
		// identify next hop, find its config and set serviceURL and cert respectively
		nextHop := md.SFP[0]
		logwriter.LW.Logger.Debugf("Next Hop: %s", nextHop)
		nextHopConf, ok := env.Config.Sf_pool[nextHop]
		if !ok {
			logwriter.LW.Logger.WithField("sf", nextHop).Error("First SF from the SFP does not exist in config file.")
			return
		}
		serviceURL = nextHopConf.Target_sf_url
		certShownByPEP = nextHopConf.X509KeyPair_shown_by_pep_to_sf

		// @author:marie
		// translate SF identifiers into ip addresses for remaining SFs
		var ipAddresses []string
		for _, sf := range md.SFP[1:] {
			sfConf, ok := env.Config.Sf_pool[sf]
			if !ok {
				logwriter.LW.Logger.WithField("sf", sf).Error("SF id returned by SFP logic has no match in config file")
				return
			}
			ipAddresses = append(ipAddresses, sfConf.Target_sf_addr)
		}

		// @author:marie
		// finally append target service to list of SFP addresses, create a string of them and set this as header for following SFs
		ipAddresses = append(ipAddresses, serviceConf.Target_service_addr)
		addressesStr := strings.Join(ipAddresses, ",")
		logwriter.LW.Logger.Debugf("SFP as presented to following SFs: %s", addressesStr)

		req.Header.Set("sfp", addressesStr)

	}
	logwriter.LW.Logger.Debugf("Service URL: %s", serviceURL.String())

	proxy = httputil.NewSingleHostReverseProxy(serviceURL)

	proxy.ErrorLog = log.New(logwriter.LW, "", 0)
	//proxy.ErrorLog = log.New(logwriter.LW.Logger.WriterLevel(logrus.ErrorLevel), "", 0)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{certShownByPEP},
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
