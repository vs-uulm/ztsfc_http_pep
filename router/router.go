package router

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	env "local.com/leobrada/ztsfc_http_pep/env"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"local.com/leobrada/ztsfc_http_pep/logwriter"
)

type Router struct {
	tls_config       *tls.Config
	frontend         *http.Server

    // TODO: Stay here or outsource?
	ca_cert_pool_ext *x509.CertPool
	ca_cert_pool_int *x509.CertPool

	// Logger structs
    // TODO: should we use the builtin logger only?
	logger     *log.Logger
	log_writer *logwriter.LogWriter
}

func NewRouter(_log_writer *logwriter.LogWriter) (*Router, error) {
	router := new(Router)

	// Access log writer
	router.log_writer = _log_writer
	go router.log_writer.Work()

	// Load all SF certificates to operate both in server and client modes
	router.initAllCertificates(&env.Config)

	router.tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           nil,
		//ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientAuth:             tls.VerifyClientCertIfGiven,
		ClientCAs:              router.ca_cert_pool_ext,
		GetCertificate: func(cli *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// load a suitable certificate that is shown to clients according the request domain/TLS SNI
			for _, service := range env.Config.Service_pool {
				if cli.ServerName == service.Sni {
					return &service.X509KeyPair_shown_by_pep_to_client, nil
				}
			}
			return nil, fmt.Errorf("Error: Could not serve a suitable certificate for %s\n", cli.ServerName)
		},
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Frontend Loggers
	router.logger = log.New(router.log_writer, "", log.LstdFlags)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         env.Config.Pep.Listen_addr,
		TLSConfig:    router.tls_config,
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
		Handler:      mux,
		ErrorLog:     router.logger,
	}

	router.log_writer.Log("============================================================\n")
	router.log_writer.Log("A new PEP router has been created\n")
	return router, nil
}

func (router *Router) SetUpSFC() bool {
	return true
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log the http request incl. TLS information
	router.log_writer.Log("------------ HTTP packet ------------\n")
	router.log_writer.LogHTTPRequest(req)

    if !bauth.Basic_auth(w, req) {
        return
    }

	var proxy *httputil.ReverseProxy
	// HE COMES THE LOGIC IN THIS FUNCTION
	need_to_go_through_sf := router.SetUpSFC()

	// Forward packets through the SF "Logger"
	need_to_go_through_logger := true

	// need_to_go_through_sf = false

	sf_to_add_name := "dummy"
	service_to_add_name := "nginx"

	if need_to_go_through_sf {
		/*
		   Here comes a Magic:
		   Definition a set of Sfs to go through
		   ...

		   Adding SF information to the HTTP header
		   ...
		*/

		router.log_writer.Log("[ Service functions ]\n")
		router.log_writer.Log(fmt.Sprintf("    - %s\n", sf_to_add_name))
		router.log_writer.Log("[ Service ]\n")
		router.log_writer.Log(fmt.Sprintf("    %s\n", service_to_add_name))

		// Temporary Solution
		service_to_add := env.Config.Service_pool[service_to_add_name]
		/*
		   req.Header.Add("service", service_to_add.Dst_url.String())
		*/
		// TODO CRUCIAL: Delete existing SFP headers for security reasons.
		sfp, ok := req.Header["Sfp"]
		if ok {
			req.Header.Del("Sfp")
		}
		sfp = append(sfp, service_to_add.Target_service_addr)
		req.Header["Sfp"] = sfp

		// Set the SF "Logger" verbosity level
		if need_to_go_through_logger {
			LoggerHeaderName := "Sfloggerlevel"
			_, ok := req.Header[LoggerHeaderName]
			if ok {
				req.Header.Del(LoggerHeaderName)
			}
			// req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d", SFLOGGER_PRINT_EMPTY_FIELDS | SFLOGGER_PRINT_TLS_MAIN_INFO)}
			// req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d", SFLOGGER_PRINT_TLS_MAIN_INFO | SFLOGGER_PRINT_RAW)}
			req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d",
				//                        logwriter.SFLOGGER_REGISTER_PACKETS_ONLY |
				logwriter.SFLOGGER_PRINT_GENERAL_INFO|
					logwriter.SFLOGGER_PRINT_HEADER_FIELDS|
					logwriter.SFLOGGER_PRINT_TRAILERS|
					logwriter.SFLOGGER_PRINT_BODY|
					logwriter.SFLOGGER_PRINT_FORMS|
					logwriter.SFLOGGER_PRINT_FORMS_FILE_CONTENT|
					//                        logwriter.SFLOGGER_PRINT_TLS_MAIN_INFO |
					//                        logwriter.SFLOGGER_PRINT_TLS_CERTIFICATES |
					//                        logwriter.SFLOGGER_PRINT_TLS_PUBLIC_KEY |
					//                        logwriter.SFLOGGER_PRINT_TLS_CERT_SIGNATURE |
					//                        logwriter.SFLOGGER_PRINT_RAW |
					logwriter.SFLOGGER_PRINT_REDIRECTED_RESPONSE|
					//                        logwriter.SFLOGGER_PRINT_EMPTY_FIELDS |
					0)}
		}

        dest, ok := env.Config.Sf_pool[sf_to_add_name]
		if !ok {
			w.WriteHeader(503)
			return
		}
		proxy = httputil.NewSingleHostReverseProxy(dest.Target_sf_url)

		// When the PEP is acting as a client; this defines his behavior
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
                // TODO: Replace it by loading the cert for the first SF in the chain
				Certificates:       []tls.Certificate{env.Config.Sf_pool[sf_to_add_name].X509KeyPair_shown_by_pep_to_sf},
				InsecureSkipVerify: true,
				ClientAuth:         tls.RequireAndVerifyClientCert,
				ClientCAs:          router.ca_cert_pool_int,
			},
		}

	} else {
		router.log_writer.Log("[ Service functions ]\n")
		router.log_writer.Log("    -\n")
		router.log_writer.Log("[ Service ]\n")
		router.log_writer.Log(fmt.Sprintf("    %s\n", service_to_add_name))
		for _, service := range env.Config.Service_pool {
	//		if req.TLS.ServerName == service.SNI {
	//			proxy = httputil.NewSingleHostReverseProxy(service.Dst_url)
			if req.TLS.ServerName == service.Sni {
				proxy = httputil.NewSingleHostReverseProxy(service.Target_service_url)

				// When the PEP is acting as a client; this defines his behavior
				// TODO: MOVE TO A BETTER PLACE
				proxy.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates:       []tls.Certificate{env.Config.Service_pool[service_to_add_name].X509KeyPair_shown_by_pep_to_client},
						InsecureSkipVerify: true,
						ClientAuth:         tls.RequireAndVerifyClientCert,
						ClientCAs:          router.ca_cert_pool_int,
					},
				}
			} else {
				w.WriteHeader(503)
				return
			}
		}
	}
	// fmt.Printf("\n%+v\n\n", req)
	proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}

func (router *Router) initAllCertificates(conf *env.Config_t) {
	var caRoot []byte
	var err error
	isErrorDetected := false

	router.ca_cert_pool_ext = x509.NewCertPool()

	// Read CA certs used for signing client certs and are accepted by the PEP
	router.log_writer.Log("Loading clients CA certificates:\n")
	for _, acceptedClientCert := range conf.Pep.Certs_pep_accepts_when_shown_by_clients {
		caRoot, err = ioutil.ReadFile(acceptedClientCert)
		if err != nil {
			isErrorDetected = true
			router.log_writer.Log(fmt.Sprintf("    - %s - FAILED\n", acceptedClientCert))
		} else {
			router.log_writer.Log(fmt.Sprintf("    - %s - OK\n", acceptedClientCert))
		}
		// Append a certificate to the pool
		router.ca_cert_pool_ext.AppendCertsFromPEM(caRoot)
	}

	router.ca_cert_pool_int = x509.NewCertPool()

	// Read CA certs used for signing client certs and are accepted by the PEP
	if len(conf.Service_pool) > 0 {
		router.log_writer.Log("Loading CA certificates for services:\n")
	}
	for service_name, service_config := range conf.Service_pool {
		caRoot, err = ioutil.ReadFile(service_config.Cert_pep_accepts_when_shown_by_service)
		if err != nil {
			isErrorDetected = true
			router.log_writer.Log(fmt.Sprintf("    %s: %s - FAILED\n", service_name,
				service_config.Cert_pep_accepts_when_shown_by_service))
		} else {
			router.log_writer.Log(fmt.Sprintf("    %s: %s - OK\n", service_name,
				service_config.Cert_pep_accepts_when_shown_by_service))
		}
		// Append a certificate to the pool
		router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
	}

	if len(conf.Sf_pool) > 0 {
		router.log_writer.Log("Loading CA certificates for service functions:\n")
	}
	for sf_name, sf_config := range conf.Sf_pool {
		caRoot, err = ioutil.ReadFile(sf_config.Cert_pep_accepts_shown_by_sf)
		if err != nil {
			isErrorDetected = true
			router.log_writer.Log(fmt.Sprintf("    %s: %s - FAILED\n", sf_name,
				sf_config.Cert_pep_accepts_shown_by_sf))
		} else {
			router.log_writer.Log(fmt.Sprintf("    %s: %s - OK\n", sf_name,
				sf_config.Cert_pep_accepts_shown_by_sf))
		}
		// Append a certificate to the pool
		router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
	}

	if isErrorDetected {
		log.Fatal("An error occurred during certificates loading. See details in the log file.")
	}
}
