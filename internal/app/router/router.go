// Package router contains the main routine of the PEP service. For each client
// request, it performs basic authentication, authorization, transformation of
// SFC into SFP and forwarding to other service functions and services.
package router

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
    "io"
    "strings"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	pdp "github.com/vs-uulm/ztsfc_http_pep/internal/app/authorization"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/blocklist"
    sfpl "github.com/vs-uulm/ztsfc_http_pep/internal/app/sfp_logic"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logger.Logger
}

func NewRouter(logger *logger.Logger) (*Router, error) {
	router := new(Router)

	// Set sysLogger to the one created in the init function
	router.sysLogger = logger

	router.tlsConfig = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           nil,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		//ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  config.Config.CAcertPoolPepAcceptsFromExt,
		GetCertificate: func(cli *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// use SNI map to load suitable certificate
			service, ok := config.Config.ServiceSniMap[cli.ServerName]
			if !ok {
				return nil, fmt.Errorf("error: could not serve a suitable certificate for %s", cli.ServerName)
			}
			return &service.X509KeyPairShownByPepToClient, nil
		},
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.Pep.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(router.sysLogger.GetWriter(), "", 0),
	}

	return router, nil
}

func addHSTSHeader(w http.ResponseWriter) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
}

func prepareSfMdHeader(req *http.Request, cpm *metadata.CpMetadata) {
    for _, sf := range cpm.SFC {
        switch sf.Name {
            case "logger":
                req.Header.Set("Logger_MD", sf.Md)
            case "ips":
                req.Header.Set("ips_md", sf.Md)
        }
    }
}

// ServeHTTP gets called if a request receives the PEP. The function implements
// the PEP's main routine: It performs basic authentication, authorization with
// help of the PEP, transformation from SFCs into SFPs with help of the SFP
// Logic, and then forwards the package along the SFP.
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	router.sysLogger.LogHTTPRequest(req)

	// Add HSTS Header
	addHSTSHeader(w)

    // BLOCKING: Check if req.RemoteAddr is on one of the blocklists
    if blocklist.BlockRequest(req) {
        io.WriteString(w, "Request has been rejected since you are on a blocklist. Contact your security advisor for more information.")
		w.WriteHeader(403)
        router.sysLogger.Infof("router: ServerHTTP(): Request from %s has been blocked since it is on a blocklist", req.RemoteAddr)
        return
    }

    // Checks if the requested resource is even served by this PEP instance
	serviceConf, ok := config.Config.ServiceSniMap[req.Host]
	if !ok {
        io.WriteString(w, "Requested resource is not provided by this PEP. Please check again.")
		w.WriteHeader(404)
        router.sysLogger.Infof("router: ServerHTTP(): %s requested a resource that is not probided by this PEP.", req.RemoteAddr)
		return
	}

    // Declares a new metadata instance in which all necessary data to process the client's request are stored in
	md := new(metadata.CpMetadata)

	// BASIC AUTHENTICATION: prompts the user for the authentication factors and evalautes them
	// Check if the user is authenticated; if not authenticate her; if that fails return an error
	// TODO: return error to client?
	// Check if user has a valid session already
	if !basic_auth.UserSessionIsValid(req, md) {
		if !basic_auth.BasicAuth(router.sysLogger, w, req) {
			// Used for measuring the time ServeHTTP runs
			// fmt.Printf("Authentication,'%s', %v\n", md.SFC, time.Since(start))
			return
		}
	}

	// AUTHORIZATION
	err := pdp.PerformAuthorization(router.sysLogger, req, md)
	if err != nil {
		router.sysLogger.WithField("issuer", "PDP").Error(err)
		return
	}

	if !md.AuthDecision {
        io.WriteString(w, md.AuthReason + ". Contact your security advisor for more information.")
		w.WriteHeader(403)
		router.sysLogger.Infof("router: ServeHTTP(): request from user %s was rejected due to the reason: %s", md.User, md.AuthReason)
		return
	}
	router.sysLogger.Debugf("router: ServeHTTP(): request from %s passed PDP. SFC: %s", req.RemoteAddr , md.SFC)

	// If user could be authenticated, define necessary variables for further processing
	var proxy *httputil.ReverseProxy
	var nextHopURL *url.URL
	var certShownByPEPToNextHop tls.Certificate
    var sfURLs []string

	// SFP LOGIC
	// If SFC is empty, skip SFP Logic
	if len(md.SFC) == 0 || config.Config.SfPool == nil {
		nextHopURL = serviceConf.TargetServiceUrl
		certShownByPEPToNextHop = serviceConf.X509KeyPairShownByPepToService
	} else {
		err = sfpl.TransformSFCIntoSFP(router.sysLogger, md)
		if err != nil {
			router.sysLogger.Errorf("router: ServeHTTP(): could not transform SFC into SFP: %v", err)
			return
		}
		router.sysLogger.Debugf("router: ServeHTTP(): request passed SFP logic. SFP: %s", md.SFP)

		if len(md.SFP) == 0 {
			router.sysLogger.Error("router: ServeHTTP(): SFP is empty altho SFC is not.")
			return
		}

	    // identify next hop, find its config and set nextHopURL and cert respectively
	    nextHop := md.SFP[0]
        // TODO: make this dynamic later
        prepareSfMdHeader(req, md)

	    router.sysLogger.Debugf("router: ServeHTTP(): next hop: %s", nextHop)

	    nextHopConf, ok := config.Config.SfPool[nextHop.Name]
	    if !ok {
		    router.sysLogger.Errorf("next hop SF '%s' from the SFP does not exist in config file.", nextHop.Name)
		    return
	    }

	    nextHopURL, err = url.Parse(nextHop.URL)
	    if err != nil {
            router.sysLogger.Errorf("router: ServeHTTP(): Could not parse URL '%s' value as URL: %v", nextHop.URL, err)
	    }

	    certShownByPEPToNextHop = nextHopConf.X509KeyPairShownByPepToSf

	    // translate SF identifiers into ip addresses for remaining SFs
        for _, sf := range md.SFP[1:] {
            sfURLs = append(sfURLs, sf.URL)
        }

	    // finally append target service to list of SFP addresses, create a string of them and set this as header for following SFs
	    sfURLs = append(sfURLs, serviceConf.TargetServiceAddr)
	    addressesStr := strings.Join(sfURLs, ",")
	    router.sysLogger.Debugf("router: ServeHTTP(): SFP as presented to following SFs: %s", addressesStr)

	    req.Header.Set("sfp", addressesStr)

	}

    router.sysLogger.Infof("router: ServeHTTP(): request from user %s (%s) forwarded to %s with SFP %v",
        md.User, md.Location, nextHopURL, sfURLs)

	proxy = httputil.NewSingleHostReverseProxy(nextHopURL)

	proxy.ErrorLog = log.New(router.sysLogger.GetWriter(), "", 0)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{certShownByPEPToNextHop},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          config.Config.CAcertPoolPepAcceptsFromInt,
		},
	}

	proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
