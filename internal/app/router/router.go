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

	//	"strings"
	"time"

	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	//	pdp "local.com/leobrada/ztsfc_http_pep/authorization"
	//	sfpl "local.com/leobrada/ztsfc_http_pep/sfp_logic"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	logWriter *logwriter.LogWriter
}

func NewRouter() (*Router, error) {
	router := new(Router)

	router.tlsConfig = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           nil,
		//ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientAuth: tls.VerifyClientCertIfGiven,
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
		ErrorLog:     log.New(router.logWriter.GetWriter(), "", 0),
		// ErrorLog:     log.New(logwriter.LW, "", 0),
	}

	return router, nil
}

func (router *Router) SetLogWriter(lw *logwriter.LogWriter) {
	router.logWriter = lw
}

func addHSTSHeader(w http.ResponseWriter) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
}

// ServeHTTP gets called if a request receives the PEP. The function implements
// the PEP's main routine: It performs basic authentication, authorization with
// help of the PEP, transformation from SFCs into SFPs with help of the SFP
// Logic, and then forwards the package along the SFP.
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// Add HSTS Header
	addHSTSHeader(w)

	// Used for measuring the time ServeHTTP runs
	//start := time.Now()

	//var err error
	// RM FOR PRODUCTIVE
	md := new(metadata.CpMetadata)

	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	router.logWriter.LogHTTPRequest(req)

	// BASIC AUTHENTICATION
	// Check if the user is authenticated; if not authenticate her; if that fails return an error
	// TODO: return error to client?
	// Check if user has a valid session already
	// RM FOR PRODUCTIVE
	if !basic_auth.UserSessionIsValid(req, md) {
		if !basic_auth.BasicAuth(w, req) {
			// Used for measuring the time ServeHTTP runs
			// fmt.Printf("Authentication,'%s', %v\n", md.SFC, time.Since(start))
			return
		}
	}

	// AUTHORIZATION
	// RM FOR PRODUCTIVE
	// pdp.SetLogWriter(router.logWriter)
	//err = pdp.PerformAuthorization(req, md)
	// observe errors and abort routine if something goes wrong
	// @author:marie
	//if err != nil {
	//	logwriter.LW.Logger.WithField("issuer", "PDP").Error(err)
	//	return
	//}

	// RM FOR PRODUCTIVE
	//if !md.AuthDecision {
	//	logwriter.LW.Logger.Info("Request was rejected due to too low trust score")
	//	w.WriteHeader(503)
	//	return
	//}
	//logwriter.LW.Logger.Debugf("Request passed PDP. SFC: %s", md.SFC)

	// If user could be authenticated, create ReverseProxy variable for the connection to serve
	var proxy *httputil.ReverseProxy
	var serviceURL *url.URL
	var certShownByPEP tls.Certificate

	//serviceConf, ok := config.Config.ServiceSniMap[md.Resource]
	serviceConf, ok := config.Config.ServiceSniMap[req.Host]
	if !ok {
		router.logWriter.WithField("sni", req.Host).Error("Requested SNI has no match in config file.")
		return
	}

	// SFP LOGIC
	// TODO: Check what happens if sf_pool in conf.yml is empty
	// only connect to SFP logic, if SFC is not empty
	// @author:marie
	//if len(md.SFC) == 0 {

	//	logwriter.LW.Logger.Debug("SFC is empty. Thus, no forwarding to SFP logic")
	//	serviceURL = serviceConf.TargetServiceUrl
	//	certShownByPEP = serviceConf.X509KeyPairShownByPepToService

	//} else {
	//  sfp1.SetLogWriter(router.logWriter)
	//	err = sfpl.TransformSFCintoSFP(md)
	//	// observe errors and abort routine if something goes wrong
	//	// @author:marie
	//	if err != nil {
	//		logwriter.LW.Logger.WithField("issuer", "SFP Logic").Error(err)
	//		return
	//	}
	//	logwriter.LW.Logger.Debugf("Request passed SFP logic. SFP: %s", md.SFP)

	//	if len(md.SFP) == 0 {
	//		logwriter.LW.Logger.Error("SFP is empty, even though SFC is not")
	//		return
	//	}

	//	// identify next hop, find its config and set serviceURL and cert respectively
	//	// @author:marie
	//	nextHop := md.SFP[0]
	//	logwriter.LW.Logger.Debugf("Next Hop: %s", nextHop)
	//	nextHopConf, ok := config.Config.SfPool[nextHop.Name]
	//	if !ok {
	//		logwriter.LW.Logger.WithField("sf", nextHop).Error("First SF from the SFP does not exist in config file.")
	//		return
	//	}
	//	serviceURL, err = url.Parse(nextHop.Address)
	//	if err != nil {
	//		logwriter.LW.Logger.WithField("address", nextHop.Address).Error("Could not parse address value as URL.")
	//	}
	//	certShownByPEP = nextHopConf.X509KeyPairShownByPepToSf

	//	// translate SF identifiers into ip addresses for remaining SFs
	//	// @author:marie
	//	var ipAddresses []string
	//	for _, sf := range md.SFP[1:] {

	//		ipAddresses = append(ipAddresses, sf.Address)
	//	}

	//	// finally append target service to list of SFP addresses, create a string of them and set this as header for following SFs
	//	// @author:marie
	//	ipAddresses = append(ipAddresses, serviceConf.TargetServiceAddr)
	//	addressesStr := strings.Join(ipAddresses, ",")
	//	logwriter.LW.Logger.Debugf("SFP as presented to following SFs: %s", addressesStr)

	//	req.Header.Set("sfp", addressesStr)

	//}
	//logwriter.LW.Logger.Debugf("Service URL: %s", serviceURL.String())
	serviceURL = serviceConf.TargetServiceUrl
	router.logWriter.Debugf("Service URL: %s", serviceURL.String())
	certShownByPEP = serviceConf.X509KeyPairShownByPepToService
	router.logWriter.Debugf("Service URL: %s", serviceConf.TargetServiceAddr)

	proxy = httputil.NewSingleHostReverseProxy(serviceURL)

	proxy.ErrorLog = log.New(router.logWriter.GetWriter(), "", 0)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{certShownByPEP},
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          config.Config.CAcertPoolPepAcceptsFromInt,
		},
	}

	proxy.ServeHTTP(w, req)

	// Used for measuring the time ServeHTTP runs
	// fmt.Printf("SFC: %s with exec time: %v\n", md.SFC, time.Since(start))
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
