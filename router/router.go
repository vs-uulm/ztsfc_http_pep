package router

import (
	"crypto/tls"
    "strings"
	"fmt"
	"log"
    "net/url"
	"net/http"
	"net/http/httputil"
	"time"
    pdp "local.com/leobrada/ztsfc_http_pep/authorization"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	env "local.com/leobrada/ztsfc_http_pep/env"
    metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
	sfpl "local.com/leobrada/ztsfc_http_pep/sfp_logic"
)

type Router struct {
	tls_config *tls.Config
	frontend   *http.Server
	lw         *logwriter.LogWriter
}

func NewRouter(lw *logwriter.LogWriter) (*Router, error) {
	router := new(Router)
	router.lw = lw

	router.tls_config = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           nil,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		//ClientAuth:				tls.VerifyClientCertIfGiven,
		ClientCAs: env.Config.CA_cert_pool_pep_accepts_from_ext,
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

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         env.Config.Pep.Listen_addr,
		TLSConfig:    router.tls_config,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(lw, "", 0),
	}

    //http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 10000
    //http.DefaultTransport.(*http.Transport).TLSHandshakeTimeout = 0 * time.Second

	return router, nil
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // Used for measuring the time ServeHTTP runs
//    start := time.Now()
    md := new(metadata.Cp_metadata)

	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	logwriter.Log_writer.LogHTTPRequest(req)

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
    pdp.PerformAuthorization(req, md)

    if !md.Auth_decision {
        fmt.Println("Request was rejected due to too low trust score")
        w.WriteHeader(403)
        return
    }

    fmt.Printf("SFC: %s\n", md.SFC)

    // SFP LOGIC
    sfpl.TransformSFCintoSFP(md)

	// If user could be authenticated, create ReverseProxy variable for the connection to serve
	var proxy *httputil.ReverseProxy
    var service_url *url.URL

    //fmt.Printf("BEFORE JOINING: %s\n", md.SFP)

    if len(md.SFP) == 0 {
        service_url, _ = url.Parse("https://10.5.0.53:443")
    } else {
        md.SFP = md.SFP + ",https://10.5.0.53:443"
        sfp_slices := strings.Split(md.SFP, ",")
        next_hop := sfp_slices[0]
        //fmt.Printf("Next Hop: %s\n", next_hop)
        sfp_slices = sfp_slices[1:]
        if len(sfp_slices) != 0 {
            md.SFP = strings.Join(sfp_slices[:], ",")
            req.Header.Set("sfp", md.SFP)
        }
        service_url, _ = url.Parse(next_hop)
    }

    // fmt.Printf("AFTER JOINING: %s\n", md.SFP)

    // fmt.Printf("SERVICE_RULM: %s\n", service_url.String())
    proxy = httputil.NewSingleHostReverseProxy(service_url)

    //fmt.Printf("AFTER CREATING PROXY\n")
//	if len(md.SFP) > 0 {
//
//		// Temporary Solution
//		service_to_add := env.Config.Service_pool[service_to_add_name]
//		/*
//		   req.Header.Add("service", service_to_add.Dst_url.String())
//		*/
//		// TODO CRUCIAL: Delete existing SFP headers for security reasons.
//		sfp, ok := req.Header["Sfp"]
//		if ok {
//			req.Header.Del("Sfp")
//		}
//		sfp = append(sfp, service_to_add.Target_service_addr)
//		req.Header["Sfp"] = sfp
//
//		// Set the SF "Logger" verbosity level
//		if need_to_go_through_logger {
//			LoggerHeaderName := "Sfloggerlevel"
//			_, ok := req.Header[LoggerHeaderName]
//			if ok {
//				req.Header.Del(LoggerHeaderName)
//			}
//
//			req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d",
//				// logwriter.SFLOGGER_REGISTER_PACKETS_ONLY |
//				logwriter.SFLOGGER_PRINT_GENERAL_INFO|
//					logwriter.SFLOGGER_PRINT_HEADER_FIELDS|
//					// logwriter.SFLOGGER_PRINT_BODY|
//					// logwriter.SFLOGGER_PRINT_FORMS|
//					// logwriter.SFLOGGER_PRINT_FORMS_FILE_CONTENT|
//					// logwriter.SFLOGGER_PRINT_TRAILERS|
//					//logwriter.SFLOGGER_PRINT_TLS_MAIN_INFO|
//					//logwriter.SFLOGGER_PRINT_TLS_CERTIFICATES|
//					// logwriter.SFLOGGER_PRINT_TLS_PUBLIC_KEY |
//					// logwriter.SFLOGGER_PRINT_TLS_CERT_SIGNATURE |
//					// logwriter.SFLOGGER_PRINT_RAW |
//					// logwriter.SFLOGGER_PRINT_REDIRECTED_RESPONSE|
//					// logwriter.SFLOGGER_PRINT_EMPTY_FIELDS |
//					0)}
//		}
//
//		dest, ok := env.Config.Sf_pool[sf_to_add_name]
//		if !ok {
//			w.WriteHeader(503)
//			return
//		}

   proxy.ErrorLog = log.New(router.lw, "", 0)

    // When the PEP is acting as a client; this defines his behavior
   proxy.Transport = &http.Transport{
       IdleConnTimeout: 10 * time.Second,
       MaxIdleConnsPerHost: 10000,
       TLSClientConfig: &tls.Config{
           // TODO: Replace it by loading the cert for the first SF in the chain
           Certificates:       []tls.Certificate{env.Config.Sf_pool["dummy"].X509KeyPair_shown_by_pep_to_sf},
           InsecureSkipVerify: true,
           SessionTicketsDisabled: false,
           ClientAuth:         tls.RequireAndVerifyClientCert,
           ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
       },
   }

//	} else {
//		//logr.Log_writer.Log("[ Service functions ]\n")
//		//logr.Log_writer.Log("    -\n")
//		//logr.Log_writer.Log("[ Service ]\n")
//		//logr.Log_writer.Log(fmt.Sprintf("    %s\n", service_to_add_name))
//		for _, service := range env.Config.Service_pool {
//			//		if req.TLS.ServerName == service.SNI {
//			//			proxy = httputil.NewSingleHostReverseProxy(service.Dst_url)
//			if req.TLS.ServerName == service.Sni {
//				proxy = httputil.NewSingleHostReverseProxy(service.Target_service_url)
//
//				// When the PEP is acting as a client; this defines his behavior
//				// TODO: MOVE TO A BETTER PLACE
//				proxy.Transport = &http.Transport{
//					TLSClientConfig: &tls.Config{
//						Certificates:       []tls.Certificate{env.Config.Service_pool[service_to_add_name].X509KeyPair_shown_by_pep_to_service},
//						InsecureSkipVerify: true,
//						ClientAuth:         tls.RequireAndVerifyClientCert,
//						ClientCAs:          env.Config.CA_cert_pool_pep_accepts_from_int,
//					},
//				}
//			} else {
//				w.WriteHeader(503)
//				return
//			}
//		}
//	}

	proxy.ServeHTTP(w, req)
    //proxies.Service_proxy.ServeHTTP(w, req)
  // fmt.Printf("'%s', %v\n", md.SFC, time.Since(start))
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}
