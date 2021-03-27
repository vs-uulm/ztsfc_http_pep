package router

// Super comment for a super role

import (
    // "os"
    // "strings"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    env "local.com/leobrada/ztsfc_http_pep/env"
    pwAuth "local.com/leobrada/ztsfc_http_pep/pwAuth"
    sf_info "local.com/leobrada/ztsfc_http_pep/sf_info"
    "local.com/leobrada/ztsfc_http_pep/trustCalculation"
    "log"
    "net/http"
    "net/http/httputil"
    "time"
    "local.com/leobrada/ztsfc_http_pep/logwriter"
    "net"
)

// FOR TESTING:
var forward bool = false

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
    logger *log.Logger
    ca_cert_pool_ext *x509.CertPool
    ca_cert_pool_int *x509.CertPool

    logChannel chan []byte
    logWriter *logwriter.LogWriter

    // Map of available Service Functions
    sf_pool map[string]sf_info.ServiceFunctionInfo

    // Proxy server serving the incoming requests
    service_pool map[string]sf_info.ServiceFunctionInfo // the key represents the SNI; the value is the respective proxy serving the request addressed to the SNI

    trustCalc trustCalculation.TrustCalculation         // Package for calculation of trust - Based on that request is blocked, send to DPI or send to service
}

func NewRouter(_service_pool map[string]sf_info.ServiceFunctionInfo, _sf_pool map[string]sf_info.ServiceFunctionInfo) (*Router, error) {
    router := new(Router)
    router.init_ca_cert_pools(&env.Config)

    // Create a logging channel
    router.logChannel = make(chan []byte, 128)

    // Create a new log writer
    router.logWriter = logwriter.NewLogWriter("./access.log", router.logChannel, 5)

    // Run main loop of logWriter
    go router.logWriter.Work()

    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: true,
        Certificates: nil,
        ClientAuth: tls.VerifyClientCertIfGiven,                                    // client authentication with password or certificate possible -> Client certificate not mandatory
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

    router.trustCalc = trustCalculation.NewTrustCalculation(router.logChannel)

    return router, nil
}

// Printing request details
// ONLY FOR TESTING
func (router *Router) printRequest(w http.ResponseWriter, req *http.Request) {
    fmt.Printf("Method: %s\n", req.Method)
    fmt.Printf("URL: %s\n", req.URL)
    fmt.Printf("Protocol Version: %d.%d\n", req.ProtoMajor, req.ProtoMinor)
    fmt.Println("===================HEADER FIELDS=======================")
    for key, value := range req.Header {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Printf("Body: %s\n", "TBD")
    fmt.Printf("Content Length: %d\n", req.ContentLength)
    fmt.Printf("Transfer Encoding: %v\n", req.TransferEncoding)
    fmt.Printf("Close: %v\n", req.Close)
    fmt.Printf("Host: %s\n", req.Host)
    fmt.Println("====================FORM======================")
    if err := req.ParseForm(); err == nil {
        for key, value := range req.Form {
            fmt.Printf("%s: %v\n", key, value)
        }
    }
    fmt.Println("==========================================")
    fmt.Println("====================POST FORM======================")
    for key, value := range req.PostForm {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Println("====================MULTIPART FORM======================")
    if err := req.ParseMultipartForm(100); err == nil {
        for key, value := range req.MultipartForm.Value {
            fmt.Printf("%s: %v\n", key, value)
        }
    }
    fmt.Println("==========================================")
    fmt.Println("===================TRAILER HEADER=======================")
    for key, value := range req.Trailer {
        fmt.Printf("%s: %v\n", key, value)
    }
    fmt.Println("==========================================")
    fmt.Printf("Remote Address: %s\n", req.RemoteAddr)
    fmt.Printf("Request URI: %s\n", req.RequestURI)
    fmt.Printf("TLS: %s\n", "TBD")
    fmt.Printf("Cancel: %s\n", "TBD")
    fmt.Printf("Reponse: %s\n", "TBD")
}
// END TESTING
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
    router.LogHTTPRequest(req, 1)
    router.Log("\nNew request-----------------------------------\n")

    if req.URL.Path == "/pwAuth" {                              // Check, if user requested the Password-Authentication site
        username, failedAuth := pwAuth.PasswordAuthentication(w, req, router.trustCalc.GetDataSources())
        if failedAuth {
            router.Log("User " + username + " failed password authentication\n")
        }
        return                                                  // When the password authentication site was accessed, no further processing is necessary, because no service was accessed
    }

    // Check for right user
   /* name, err := req.Cookie("Username")
    if err == nil && name.Value != "alex" {
        router.Log("Unknown user " + name.Value + " -> block\n")
        pwAuth.PasswordAuthentication(w, req)
        return
    }*/

    forwardSFC, block := router.trustCalc.ForwardingDecision(req) // calculate trust and decide according to trust, how the request is handled

    // --- Specification PEP behavior ----
    // Here it can be specified, if the PEP should send all requests to the PEP or to the service (relevant for some cases in the evaluation)
    //forwardSFC = false
    //block = false

    if block {                                                    // Check, if trust was to low and request is blocked
        w.WriteHeader(401)
        router.Log("---Request blocked\n")
        fmt.Println("Request blocked")
        return
    }else {
        router.Log("---Request forwarded\n")
    }

    var proxy *httputil.ReverseProxy
    // HE COMES THE LOGIC IN THIS FUNCTION
    //need_to_go_through_sf := router.SetUpSFC()
    sf_to_add_name := "dpi"
    service_to_add_name := "nginx"

    if (forwardSFC) {
        router.Log("Request send to DPI\n")
        /*
            Here comes a Magic:
            Definition a set of Sfs to go through
            ...

            Adding SF information to the HTTP header
            ...
        */
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

        dest, ok := router.sf_pool[sf_to_add_name]
        if !ok {
            w.WriteHeader(503)
            return
        }
        proxy = httputil.NewSingleHostReverseProxy(dest.Dst_url)
        proxy.Transport = &http.Transport{
            MaxIdleConns: 100,
            IdleConnTimeout: 10* time.Second,
            Dial: (&net.Dialer{
                Timeout:   10 * time.Second,                        // Specifies timeout to establish a connection
            }).Dial,
        }



       /* proxy.ModifyResponse = func(resp *http.Response) error {
                resp.Request.URL.Scheme="https"
                return nil
            }
*/
    } else {
        for _, service := range router.service_pool {
            if req.TLS.ServerName == service.SNI {
                proxy = httputil.NewSingleHostReverseProxy(service.Dst_url)
                proxy.Transport = &http.Transport{
                    MaxIdleConns: 100,
                    IdleConnTimeout: 10 * time.Second,
                    Dial: (&net.Dialer{
                        Timeout:   10 * time.Second,                // Specifies timeout to establish a connection
                    }).Dial,
                }
            } else {
                w.WriteHeader(503)
                return
            }
        }
    }
    proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}

func (router *Router) init_ca_cert_pools(conf *env.Config_t) {
    var caRoot []byte
    var err error

    router.ca_cert_pool_ext = x509.NewCertPool()

    // Read CA certs used for signing client certs and are accepted by the PEP
    for _, acceptedClientCert := range conf.Pep.Certs_pep_accepts_when_shown_by_clients {
        caRoot, err = ioutil.ReadFile(acceptedClientCert)
        if err != nil {
            log.Fatal("ReadFile: ", err)
        }
      // Append a certificate to the pool
        router.ca_cert_pool_ext.AppendCertsFromPEM(caRoot)
    }

    router.ca_cert_pool_int = x509.NewCertPool()

    // Read CA certs used for signing client certs and are accepted by the PEP
    for _, service_config := range(conf.Service_pool) {
        caRoot, err = ioutil.ReadFile(service_config.Cert_pep_accepts_when_shown_by_service)
        if err != nil {
            log.Fatal("ReadFile: ", err)
        }
        // Append a certificate to the pool
        router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
    }

    for _, sf_config := range(conf.Sf_pool) {
        caRoot, err = ioutil.ReadFile(sf_config.Cert_pep_accepts_shown_by_sf)
        if err != nil {
            log.Fatal("ReadFile: ", err)
        }
        // Append a certificate to the pool
        router.ca_cert_pool_int.AppendCertsFromPEM(caRoot)
    }
}

func (router *Router) Log(s string) {
  router.logChannel <- []byte(s)
}

func (router *Router) LogHTTPRequest(req *http.Request, loglevel int) {
  // Make a string to log
  t := time.Now()
  ts := fmt.Sprintf("%d/%d/%d %02d:%02d:%02d ",
                     t.Year(),
                        t.Month(),
                           t.Day(),
                              t.Hour(),
                                   t.Minute(),
                                         t.Second())
  s := fmt.Sprintf("%s,%s,%s,%s,%t,%t,%s,success\n",
                    ts,
                       req.RemoteAddr,
                          req.TLS.ServerName,
                             matchTLSConst(req.TLS.Version),
                                req.TLS.HandshakeComplete,
                                   req.TLS.DidResume,
                                      matchTLSConst(req.TLS.CipherSuite))

  router.Log(s)
}