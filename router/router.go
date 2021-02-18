package router

import (
	"crypto/tls"
	"fmt"
	env "local.com/leobrada/ztsfc_http_pep/env"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	logr "local.com/leobrada/ztsfc_http_pep/logwriter"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

type Router struct {
	tls_config       *tls.Config
	frontend         *http.Server

	// Logger structs
    // TODO: should we use the builtin logger only?
	logger     *log.Logger
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
		ClientAuth:             tls.VerifyClientCertIfGiven,
		ClientCAs:              env.Config.CA_cert_pool_pep_accepts_from_ext,
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
	router.logger = log.New(logr.Log_writer, "", log.LstdFlags)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         env.Config.Pep.Listen_addr,
		TLSConfig:    router.tls_config,
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
		Handler:      mux,
		ErrorLog:     router.logger,
	}

	logr.Log_writer.Log("============================================================\n")
	logr.Log_writer.Log("A new PEP router has been created\n")
	return router, nil
}

func (router *Router) SetUpSFC() bool {
	return true
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Log all http requests incl. TLS information
	logr.Log_writer.Log("------------ HTTP packet ------------\n")
	logr.Log_writer.LogHTTPRequest(req)

    // Check if the user is authenticated; if not authenticate him/her; if that fails return an error
    // TODO: return error to client?
    if !bauth.Basic_auth(w, req) {
        return
    }

    // If user could be authenticated, create ReverseProxy variable for the connection to serve
	var proxy *httputil.ReverseProxy

    // ===== GARBAGE STARTING FROM HERE =====

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

		logr.Log_writer.Log("[ Service functions ]\n")
		logr.Log_writer.Log(fmt.Sprintf("    - %s\n", sf_to_add_name))
		logr.Log_writer.Log("[ Service ]\n")
		logr.Log_writer.Log(fmt.Sprintf("    %s\n", service_to_add_name))

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
				//                        logr.SFLOGGER_REGISTER_PACKETS_ONLY |
				logr.SFLOGGER_PRINT_GENERAL_INFO|
					logr.SFLOGGER_PRINT_HEADER_FIELDS|
					logr.SFLOGGER_PRINT_TRAILERS|
					logr.SFLOGGER_PRINT_BODY|
					logr.SFLOGGER_PRINT_FORMS|
					logr.SFLOGGER_PRINT_FORMS_FILE_CONTENT|
					//                        logr.SFLOGGER_PRINT_TLS_MAIN_INFO |
					//                        logr.SFLOGGER_PRINT_TLS_CERTIFICATES |
					//                        logr.SFLOGGER_PRINT_TLS_PUBLIC_KEY |
					//                        logr.SFLOGGER_PRINT_TLS_CERT_SIGNATURE |
					//                        logr.SFLOGGER_PRINT_RAW |
					logr.SFLOGGER_PRINT_REDIRECTED_RESPONSE|
					//                        logr.SFLOGGER_PRINT_EMPTY_FIELDS |
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
				ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
			},
		}

	} else {
		logr.Log_writer.Log("[ Service functions ]\n")
		logr.Log_writer.Log("    -\n")
		logr.Log_writer.Log("[ Service ]\n")
		logr.Log_writer.Log(fmt.Sprintf("    %s\n", service_to_add_name))
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
				        ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
					},
				}
			} else {
				w.WriteHeader(503)
				return
			}
		}
	}

    // ======= END GARBAGE =======

	proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}

