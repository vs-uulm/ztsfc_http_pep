package main

import (
	"crypto/x509"
	"flag"
	"net/http"

	"github.com/sirupsen/logrus"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	env "local.com/leobrada/ztsfc_http_pep/env"
	sf_init "local.com/leobrada/ztsfc_http_pep/init"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
	router "local.com/leobrada/ztsfc_http_pep/router"
)

var (
	conf_file_path  string
	log_file_path   string
	log_level       string
	ifTextFormatter bool

	// An instance of logwriter based on logrus
	lw *logwriter.LogWriter
)

func init() {
	flag.StringVar(&log_file_path, "log-to", "./pep.log", "Path to log file. Write 'stdout' to print to stdout")
	flag.StringVar(&conf_file_path, "c", "./conf.yml", "Path to user defined yml config file")
	flag.StringVar(&log_level, "log-level", "error", "Log level from the next set: debug, info, warning, error")
	flag.BoolVar(&ifTextFormatter, "text", false, "Use a text format instead of JSON to log messages")

	// Operating input parameters
	flag.Parse()

	lw = logwriter.New(log_file_path, log_level, ifTextFormatter)
	sysLogger := lw.Logger.WithFields(logrus.Fields{"type": "system"})
	sf_init.SetupCloseHandler(lw)

	// Loading all config parameter from config file defined in "conf_file_path"
	err := env.LoadConfig(conf_file_path, sysLogger)
	if err != nil {
		sysLogger.Fatalf("Loading logger configuration from %s - ERROR: %v", conf_file_path, err)
	} else {
		sysLogger.Debugf("Loading logger configuration from %s - OK", conf_file_path)
	}

	// Loading all service related information into env.Config
	err = sf_init.LoadServicePool(env.Config, sysLogger)
	if err != nil {
		sysLogger.Fatalf("Loading service pool - ERROR: %v", err)
	} else {
		sysLogger.Debug("Loading service pool - OK")
	}

	// Loading all sf related information into env.Config
	err = sf_init.LoadSfPool(env.Config, sysLogger)
	if err != nil {
		sysLogger.Fatalf("Loading service functions pool - ERROR: %v", err)
	} else {
		sysLogger.Debug("Loading service functions pool - OK")
	}

	// Create Certificate Pools for the CA certificates used by the PEP
	env.Config.CA_cert_pool_pep_accepts_from_ext = x509.NewCertPool()
	env.Config.CA_cert_pool_pep_accepts_from_int = x509.NewCertPool()

	// Load all CA certificates
	sf_init.InitAllCACertificates(sysLogger)
	sysLogger.Debug("Loading CA certificates pool - OK")

	// Init Reverse Proxies used for the modules
	proxies.Basic_auth_proxy = proxies.NewBasicAuthProxy()
	proxies.Pdp_client_pool = proxies.NewClientPool()
	proxies.Sfp_logic_client_pool = proxies.NewClientPool()

	// TEST
	//proxies.Service_proxy = proxies.NewServiceProxy()

	// Init RSA Keys für JWT
	bauth.Jwt_pub_key = bauth.ParseRsaPublicKeyFromPemStr("./basic_auth/jwt_test_pub.pem")
	bauth.MySigningKey = bauth.ParseRsaPrivateKeyFromPemStr("./basic_auth/jwt_test_priv.pem")
	////bauth.Jwt_priv_key = bauth.ParseRsaPublicKeyFromPemStr("./basic_auth/jwt_test_pub.pem")
}

func main() {
	// Create new PEP router
	pep, err := router.NewRouter(lw)
	if err != nil {
		lw.Logger.Fatalf("Fatal error during new router creation: %v", err)
	} else {
		lw.Logger.WithFields(logrus.Fields{"type": "system"}).Debug("New router is successfully created")
	}

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		lw.Logger.Fatalf("ListenAndServeTLS Fatal Error: %v", err)
	}
}
