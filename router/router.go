package router

import (
    // "os"
    // "strings"
    "crypto/tls"
    "net/http"
    "net/http/httputil"
    "time"
    "fmt"
    "io/ioutil"
    "log"
    "crypto/x509"
    env "local.com/leobrada/ztsfc_http_pep/env"
    sf_info "local.com/leobrada/ztsfc_http_pep/sf_info"
    
    "local.com/leobrada/ztsfc_http_pep/logwriter"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
)

const (
    SFLOGGER_REGISTER_PACKETS_ONLY  uint32  = 1 << iota
    SFLOGGER_PRINT_GENERAL_INFO
    SFLOGGER_PRINT_HEADER_FIELDS
    SFLOGGER_PRINT_TRAILERS
    SFLOGGER_PRINT_BODY
    SFLOGGER_PRINT_FORMS
    SFLOGGER_PRINT_FORMS_FILE_CONTENT
    SFLOGGER_PRINT_TLS_MAIN_INFO
    SFLOGGER_PRINT_TLS_CERTIFICATES
    SFLOGGER_PRINT_TLS_PUBLIC_KEY
    SFLOGGER_PRINT_TLS_CERT_SIGNATURE
    SFLOGGER_PRINT_RAW
    SFLOGGER_PRINT_REDIRECTED_RESPONSE
    SFLOGGER_PRINT_EMPTY_FIELDS
)

// TODO: MUST BE UPDATED
func loadCaPool(path string) (ca_cert_pool *x509.CertPool) {
    nginx_root_crt, err := ioutil.ReadFile(path)
    if err != nil {
        log.Fatal("ReadFile: ", err)
    }
    ca_cert_pool = x509.NewCertPool()
    ca_cert_pool.AppendCertsFromPEM(nginx_root_crt)

    return
}

type Router struct {
    tls_config *tls.Config
    frontend *http.Server
    ca_cert_pool_ext *x509.CertPool
    ca_cert_pool_int *x509.CertPool
    
    // Map of available Service Functions 
    sf_pool map[string]sf_info.ServiceFunctionInfo

    // Proxy server serving the incoming requests
    service_pool map[string]sf_info.ServiceFunctionInfo // the key represents the SNI; the value is the respective proxy serving the request addressed to the SNI
    
    // Logger structs
    logger *log.Logger
    logLevel int
    logChannel chan []byte
    logWriter *logwriter.LogWriter
}

func NewRouter(_service_pool map[string]sf_info.ServiceFunctionInfo,
               _sf_pool      map[string]sf_info.ServiceFunctionInfo,
               _log_level    int) (*Router, error) {
    router := new(Router)
    router.logLevel = _log_level

    // Create a log channel
    router.logChannel = make(chan []byte, 128)

    // Create a new log writer
    router.logWriter = logwriter.NewLogWriter("./access.log", router.logChannel, 5)

    // Run main loop of logWriter
    go router.logWriter.Work()
    
    router.Log(DEBUG, "============================================================\n")
    router.Log(DEBUG, "A new PEP router has been created\n")

    // Load all SF certificates to operate both in server and client modes
    router.initAllCertificates(&env.Config)
    
    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: nil,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: router.ca_cert_pool_ext,
        GetCertificate: func(cli *tls.ClientHelloInfo) (*tls.Certificate, error) {
            // Load Let's Encrypt Certificate that is shown to Clients
            for _, service := range env.Config.Service_pool {
                if cli.ServerName == service.Sni {
                    external_pep_service_cert, err := tls.LoadX509KeyPair(
                        service.Cert_shown_by_pep_to_clients_matching_sni,
                        service.Privkey_for_cert_shown_by_pep_to_client)
                    if err != nil {
                        log.Fatal("[Router.NewRouter]: LoadX509KeyPair: ", err)
                    }
                    return &external_pep_service_cert, nil
                }
            }
            return nil, fmt.Errorf("Error: Could not serve a suitable certificate for %s\n", cli.ServerName)
        },
    }

    // Frontend Handlers
    mux := http.NewServeMux()
    mux.Handle("/", router)

    // Frontend Loggers
    router.logger = log.New(logwriter.LogWriter{}, "", log.LstdFlags)

    router.frontend = &http.Server {
        Addr: env.Config.Pep.Listen_addr,
        TLSConfig: router.tls_config,
        ReadTimeout: time.Second * 5,
        WriteTimeout: time.Second *5,
        Handler: mux,
        ErrorLog: router.logger,
    }

    router.service_pool = _service_pool
    router.sf_pool = _sf_pool

    return router, nil
}

func middlewareDummy(w http.ResponseWriter, req *http.Request) (bool){
    var username, password string
    form := `<html>
            <body>
            <form action="/" method="post">
            <label for="fname">Username:</label>
            <input type="text" id="username" name="username"><br><br>
            <label for="lname">Password:</label>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Submit">
            </form>
            </body>
            </html>
            `

    _, err := req.Cookie("Username")
    if err != nil {
        if req.Method =="POST" {
            if err := req.ParseForm(); err != nil {
                fmt.Println("Parsing Error")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            nmbr_of_postvalues := len(req.PostForm)
            if nmbr_of_postvalues != 2 {
                fmt.Println("Too many Post Form Values")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            usernamel, exist := req.PostForm["username"]
            username = usernamel[0]
            if !exist || username != "alex" {
                fmt.Println("username not present or wrong")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            passwordl, exist := req.PostForm["password"]
            password = passwordl[0]
            if !exist || password != "test" {
                fmt.Println("password not present or wrong")
                w.WriteHeader(401)
                w.Header().Set("Content-Type", "text/html; charset=utf-8")
                fmt.Fprintf(w, form)
                return false
            }

            cookie := http.Cookie{
                Name: "Username",
                Value: username,
                MaxAge: 10,
                Path: "/",
            }
            http.SetCookie(w, &cookie)
            http.Redirect(w, req, "https://service1.testbed.informatik.uni-ulm.de", 303)
            return true

        } else {
            fmt.Println("only post methods are accepted in this state")
            w.WriteHeader(401)
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            fmt.Fprintf(w, form)
            return false
        }
    }
    return true
}

func (router *Router) SetUpSFC() bool {
    return true
}

func matchTLSConst(input uint16) string {
    switch input {
    // TLS VERSION
    case 0x0300:
        return "VersionSSL30"
    case 0x0301:
        return "VersionTLS10"
    case 0x0302:
        return "VersionTLS11"
    case 0x0303:
        return "VersionTLS12"
    case 0x0304:
        return "VersionTLS13"
    // TLS CIPHER SUITES
    case 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA"
    case 0x000a:
        return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    case 0x002f:
        return "TLS_RSA_WITH_AES_128_CBC_SHA"
    case 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA"
    case 0x003c:
        return "TLS_RSA_WITH_AES_128_CBC_SHA256"
    case 0x009c:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256"
    case 0x009d:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384"
    case 0xc007:
        return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    case 0xc009:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    case 0xc00a:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256"
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384"
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256"
    case 0x5600:
        return "TLS_FALLBACK_SCSV"
    default:
        return "unsupported"
    }
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // Log the http request
    router.Log(DEBUG, "------------ HTTP packet ------------\n")
    router.LogHTTPRequest(DEBUG, req)

    var proxy *httputil.ReverseProxy
    // HE COMES THE LOGIC IN THIS FUNCTION
    need_to_go_through_sf := router.SetUpSFC()
    
    
    // Forward packets through the SF "Logger"
    need_to_go_through_logger := true
    
    // need_to_go_through_sf = false
    
    sf_to_add_name := "log"
    service_to_add_name := "nginx"

    if (need_to_go_through_sf) {
        /*
            Here comes a Magic:
            Definition a set of Sfs to go through
            ...

            Adding SF information to the HTTP header
            ...
        */
        
        router.Log(DEBUG, "[ Service functions ]\n")
        router.Log(DEBUG, fmt.Sprintf("    - %s\n", sf_to_add_name))
        router.Log(DEBUG, "[ Service ]\n")
        router.Log(DEBUG, fmt.Sprintf("    %s\n", service_to_add_name))
        
        // Temporary Solution
        service_to_add := router.service_pool[service_to_add_name]
        /*
        req.Header.Add("service", service_to_add.Dst_url.String())
        */
        // TODO CRUCIAL: Delete existing SFP headers for security reasons.
        sfp, ok := req.Header["Sfp"]
        if ok {
            req.Header.Del("Sfp")
        }
        sfp = append(sfp, service_to_add.Dst_url.String())
        req.Header["Sfp"] = sfp

        // Set the SF "Logger" verbosity level
        if (need_to_go_through_logger) {
            LoggerHeaderName := "Sfloggerlevel"
            _, ok := req.Header[LoggerHeaderName]
            if ok {
                req.Header.Del(LoggerHeaderName)
            }
            // req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d", SFLOGGER_PRINT_EMPTY_FIELDS | SFLOGGER_PRINT_TLS_MAIN_INFO)}
            // req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d", SFLOGGER_PRINT_TLS_MAIN_INFO | SFLOGGER_PRINT_RAW)}
            req.Header[LoggerHeaderName] = []string{fmt.Sprintf("%d",
                        SFLOGGER_REGISTER_PACKETS_ONLY |
                        SFLOGGER_PRINT_GENERAL_INFO |
                        SFLOGGER_PRINT_HEADER_FIELDS |
                        SFLOGGER_PRINT_TRAILERS |
                        SFLOGGER_PRINT_BODY |
                        SFLOGGER_PRINT_FORMS |
                        SFLOGGER_PRINT_FORMS_FILE_CONTENT |
                        SFLOGGER_PRINT_TLS_MAIN_INFO |
                        SFLOGGER_PRINT_TLS_CERTIFICATES |
                        SFLOGGER_PRINT_TLS_PUBLIC_KEY |
                        SFLOGGER_PRINT_TLS_CERT_SIGNATURE |
                        SFLOGGER_PRINT_RAW |
                        SFLOGGER_PRINT_REDIRECTED_RESPONSE |
                        SFLOGGER_PRINT_EMPTY_FIELDS |
                        0 )}                        
        }
    
        dest, ok := router.sf_pool[sf_to_add_name]
        if !ok {
            w.WriteHeader(503)
            return
        }
        proxy = httputil.NewSingleHostReverseProxy(dest.Dst_url)

        // When the PEP is acting as a client; this defines his behavior
        proxy.Transport = &http.Transport{
            TLSClientConfig: &tls.Config {
            Certificates: []tls.Certificate{router.service_pool[service_to_add_name].Certificate},
            InsecureSkipVerify: true,
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs: router.ca_cert_pool_int,
            },
        }

        /*
        proxy.ModifyResponse = func(resp *http.Response) error {
                resp.Header.Add("hello", "LOOL")
                return nil
            }
        */
    } else {
        router.Log(DEBUG, "[ Service functions ]\n")
        router.Log(DEBUG, "    -\n")
        router.Log(DEBUG, "[ Service ]\n")
        router.Log(DEBUG, fmt.Sprintf("    %s\n", service_to_add_name))
        for _, service := range router.service_pool {
            if req.TLS.ServerName == service.SNI {
                proxy = httputil.NewSingleHostReverseProxy(service.Dst_url)

                // When the PEP is acting as a client; this defines his behavior
                proxy.Transport = &http.Transport{
                    TLSClientConfig: &tls.Config {
                    Certificates: []tls.Certificate{router.service_pool[service_to_add_name].Certificate},
                    InsecureSkipVerify: true,
                    ClientAuth: tls.RequireAndVerifyClientCert,
                    ClientCAs: router.ca_cert_pool_int,
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
    return router.frontend.ListenAndServeTLS("","")
}

func (router *Router) initAllCertificates(conf *env.Config_t) {
    var caRoot []byte
    var err error
    isErrorDetected := false

    router.ca_cert_pool_ext = x509.NewCertPool()

    // Read CA certs used for signing client certs and are accepted by the PEP
    router.Log(DEBUG, "Loading clients CA certificates:\n")
    for _, acceptedClientCert := range conf.Pep.Certs_pep_accepts_when_shown_by_clients {
        caRoot, err = ioutil.ReadFile(acceptedClientCert)
        if err!=nil {
            isErrorDetected = true
            router.Log(DEBUG, fmt.Sprintf("    - %s - FAILED\n", acceptedClientCert))
        } else {
            router.Log(DEBUG, fmt.Sprintf("    - %s - OK\n", acceptedClientCert))
        }
        // Append a certificate to the pool
        router.ca_cert_pool_ext.AppendCertsFromPEM(caRoot)
    }

    router.ca_cert_pool_int = x509.NewCertPool()

    // Read CA certs used for signing client certs and are accepted by the PEP
    if (len(conf.Service_pool) > 0) {
        router.Log(DEBUG, "Loading CA certificates for services:\n")
    }
    for service_name, service_config := range(conf.Service_pool) {
        caRoot, err = ioutil.ReadFile(service_config.Cert_pep_accepts_when_shown_by_service)
        if err!=nil {
            isErrorDetected = true
            router.Log(DEBUG, fmt.Sprintf("    %s: %s - FAILED\n", service_name,
                                          service_config.Cert_pep_accepts_when_shown_by_service))
        } else {
            router.Log(DEBUG, fmt.Sprintf("    %s: %s - OK\n", service_name,
                                          service_config.Cert_pep_accepts_when_shown_by_service))
        }
        // Append a certificate to the pool
        router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
    }

    if (len(conf.Sf_pool) > 0) {
        router.Log(DEBUG, "Loading CA certificates for service functions:\n")
    }
    for sf_name, sf_config := range(conf.Sf_pool) {
        caRoot, err = ioutil.ReadFile(sf_config.Cert_pep_accepts_shown_by_sf)
        if err!=nil {
            isErrorDetected = true
            router.Log(DEBUG, fmt.Sprintf("    %s: %s - FAILED\n", sf_name,
                                          sf_config.Cert_pep_accepts_shown_by_sf))
        } else {
            router.Log(DEBUG, fmt.Sprintf("    %s: %s - OK\n", sf_name,
                                          sf_config.Cert_pep_accepts_shown_by_sf))
        }
        // Append a certificate to the pool
        router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
    }
    
    if isErrorDetected {
        log.Fatal("An error occurred during certificates loading. See details in the log file.")
    }
}

// The Log() function writes messages from a provided slice as space-separated string into the log
func (router *Router) Log (logLevel int, messages ...string) {
    // Nothing to do, if message's log level is lower than those, user has set
    if logLevel < router.logLevel {
        return
    }
    
    // Creates a comma-separated string out of the incoming slice of strings
    s := router.logWriter.GetLogTimeStamp()
    for _, message := range messages {
        s = s + "," + message
    }
    
    // Send the resulting string to the logging channel
    router.logChannel <- []byte(s)
}


// The LogHTTPRequest() function prints HTTP request details into the log file
func (router *Router) LogHTTPRequest(logLevel int, req *http.Request) {
    // Check if we have something to do
    if logLevel < router.logLevel {
        return
    }

    // Fill in the string with the rest data
    s := fmt.Sprintf("%s,%s,%s,%t,%t,%s,success\n",
                      req.RemoteAddr,
                         req.TLS.ServerName,
                            matchTLSConst(req.TLS.Version),
                               req.TLS.HandshakeComplete,
                                  req.TLS.DidResume,
                                     matchTLSConst(req.TLS.CipherSuite))                                        

    // Write the string to the log file
    router.Log(logLevel, s)
}