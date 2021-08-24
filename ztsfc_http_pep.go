package main

import (
	"crypto/x509"
	"flag"
	"net/http"

	"github.com/sirupsen/logrus"
	bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
	env "local.com/leobrada/ztsfc_http_pep/env"
	confInit "local.com/leobrada/ztsfc_http_pep/init"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
	router "local.com/leobrada/ztsfc_http_pep/router"
)

var (
	conf_file_path  string
	log_file_path   string
	log_level       string
	ifTextFormatter bool
)

func init() {
	flag.StringVar(&log_file_path, "log-to", "./pep.log", "Path to log file. Write 'stdout' to print to stdout")
	flag.StringVar(&conf_file_path, "c", "./conf.yml", "Path to user defined yml config file")
	flag.StringVar(&log_level, "log-level", "error", "Log level from the next set: debug, info, warning, error")
	flag.BoolVar(&ifTextFormatter, "text", false, "Use a text format instead of JSON to log messages")

	// Operating input parameters
	flag.Parse()

	logwriter.InitLogwriter(log_file_path, log_level, ifTextFormatter)
	sysLogger := logwriter.LW.Logger.WithFields(logrus.Fields{"type": "system"})

	// Loading all config parameter from config file defined in "conf_file_path"
	err := env.LoadConfig(conf_file_path, sysLogger)
	if err != nil {
		sysLogger.Fatalf("Loading logger configuration from %s - ERROR: %v", conf_file_path, err)
	} else {
		sysLogger.Debugf("Loading logger configuration from %s - OK", conf_file_path)
	}

	// Create Certificate Pools for the CA certificates used by the PEP
	env.Config.CA_cert_pool_pep_accepts_from_ext = x509.NewCertPool()
	env.Config.CA_cert_pool_pep_accepts_from_int = x509.NewCertPool()

	// Preload diverse parameters from config
	confInit.InitPepParams(sysLogger)
	confInit.InitLdapParams(sysLogger)
	confInit.InitPdpParams(sysLogger)
	confInit.InitSfplParams(sysLogger)
	confInit.InitServicePoolParams(sysLogger)
	confInit.InitSfPoolParams(sysLogger)

	// Init Reverse Proxies used for the modules
	// Basic_auth_proxy currently not needed since BasicAuth is performed as part of the PEP
	proxies.Pdp_client_pool = proxies.NewClientPool(env.Config.Pdp.Pdp_client_pool_size, env.Config.Pdp.X509KeyPair_shown_by_pep_to_pdp)
	proxies.Sfp_logic_client_pool = proxies.NewClientPool(env.Config.Sfp_logic.Sfpl_client_pool_size, env.Config.Sfp_logic.X509KeyPair_shown_by_pep_to_sfpl)

	// Init RSA Keys für JWT
	bauth.Jwt_pub_key = bauth.ParseRsaPublicKeyFromPemStr("./basic_auth/jwt_test_pub.pem")
	bauth.MySigningKey = bauth.ParseRsaPrivateKeyFromPemStr("./basic_auth/jwt_test_priv.pem")
}

func main() {

	// Code snippets useful for performance profiling:
	// defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	// defer profile.Start(profile.BlockProfile, profile.ProfilePath(".")).Stop()
	// defer profile.Start(profile.GoroutineProfile, profile.ProfilePath(".")).Stop()

	// Create new PEP router
	pep, err := router.NewRouter()
	if err != nil {
		logwriter.LW.Logger.Fatalf("Fatal error during new router creation: %v", err)
	} else {
		logwriter.LW.Logger.WithFields(logrus.Fields{"type": "system"}).Debug("New router is successfully created")
	}

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		logwriter.LW.Logger.Fatalf("ListenAndServeTLS Fatal Error: %v", err)
	}
}
