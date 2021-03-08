package main

import (
	"crypto/x509"
	"flag"
	"net/http"

	env "local.com/leobrada/ztsfc_http_pep/env"
	sf_init "local.com/leobrada/ztsfc_http_pep/init"
	router "local.com/leobrada/ztsfc_http_pep/router"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
)

var (
	conf_file_path string
	log_file_path string
	log_level string
	ifJSONformatter bool

	// An instance of logwriter based on logrus
	lw *logwriter.LogWriter
)

func init() {
	flag.StringVar(&log_file_path, "log", "./pep.log", "Path to log file")
	flag.StringVar(&conf_file_path, "c", "./conf.yml", "Path to user defined yml config file")
	flag.StringVar(&log_level, "log-level", "error", "Log level from the next set: debug, info, warning, error")
	flag.BoolVar(&ifJSONformatter, "json", false, "Use JSON format for logging messages")

	// Operating input parameters
	flag.Parse()

	lw = logwriter.New(log_file_path, log_level, ifJSONformatter)
	sf_init.SetupCloseHandler(lw)

	// Loading all config parameter from config file defined in "conf_file_path"
	err := env.LoadConfig(conf_file_path, lw)
	if err != nil {
		lw.Logger.Fatalf("Loading logger configuration from %s - ERROR: %v", conf_file_path, err)
	} else {
		lw.Logger.Debugf("Loading logger configuration from %s - OK", conf_file_path)
	}

	// Loading all service related information into env.Config
	err = sf_init.LoadServicePool(env.Config, lw)
	if err != nil {
		lw.Logger.Fatalf("Loading service pool - ERROR: %v", err)
	} else {
		lw.Logger.Debug("Loading service pool - OK")
	}

	// Loading all sf related information into env.Config
	err = sf_init.LoadSfPool(env.Config, lw)
	if err != nil {
		lw.Logger.Fatalf("Loading service functions pool - ERROR: %v", err)
	} else {
		lw.Logger.Debug("Loading service functions pool - OK")
	}

	// Create Certificate Pools for the CA certificates used by the PEP
	env.Config.CA_cert_pool_pep_accepts_from_ext = x509.NewCertPool()
	env.Config.CA_cert_pool_pep_accepts_from_int = x509.NewCertPool()

	// Load all CA certificates
	err = sf_init.InitAllCACertificates(lw)
	if err != nil {
		lw.Logger.Fatalf("Loading CA certificates pool - ERROR: %v\n", err)
	} else {
		lw.Logger.Debug("Loading CA certificates pool - OK")
	}
}

func main() {
	// Create new PEP router
	pep, err := router.NewRouter(lw)
	if err != nil {
		lw.Logger.Fatalf("Fatal error during new router creation: %v\n", err)
	} else {
		lw.Logger.Debug("New router is successfully created")
	}

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		lw.Logger.Fatalf("ListenAndServeTLS Fatal Error: %v\n", err)
	}
}
