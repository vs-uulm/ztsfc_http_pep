package main

import (
	"crypto/x509"
	"flag"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/env"
	confInit "github.com/vs-uulm/ztsfc_http_pep/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/router"
)

var (
	confFilePath    string
	logFilePath     string
	logLevel        string
	ifTextFormatter bool
)

func init() {
	flag.StringVar(&logFilePath, "log-to", "./pep.log", "Path to log file. Write 'stdout' to print to stdout")
	flag.StringVar(&confFilePath, "c", "./conf.yml", "Path to user defined yml config file")
	flag.StringVar(&logLevel, "log-level", "error", "Log level from the next set: debug, info, warning, error")
	flag.BoolVar(&ifTextFormatter, "text", false, "Use a text format instead of JSON to log messages")

	// Operating input parameters
	flag.Parse()

	logwriter.InitLogwriter(logFilePath, logLevel, ifTextFormatter)
	sysLogger := logwriter.LW.Logger.WithFields(logrus.Fields{"type": "system"})

	// Loading all config parameter from config file defined in "confFilePath"
	err := env.LoadConfig(confFilePath, sysLogger)
	if err != nil {
		sysLogger.Fatalf("Loading logger configuration from %s - ERROR: %v", confFilePath, err)
	} else {
		sysLogger.Debugf("Loading logger configuration from %s - OK", confFilePath)
	}

	// Create Certificate Pools for the CA certificates used by the PEP
	env.Config.CAcertPoolPepAcceptsFromExt = x509.NewCertPool()
	env.Config.CAcertPoolPepAcceptsFromInt = x509.NewCertPool()

	// Preload diverse parameters from config
	// (One function for each section in config.yml)
	confInit.InitDefaultValues(sysLogger)
	confInit.InitPepParams(sysLogger)
	confInit.InitBasicAuth(sysLogger)
	confInit.InitLdapParams(sysLogger)
	confInit.InitPdpParams(sysLogger)
	confInit.InitSfplParams(sysLogger)
	confInit.InitServicePoolParams(sysLogger)
	confInit.InitSfPoolParams(sysLogger)

	// Init Reverse Proxies used for the modules
	// Basic_auth_proxy currently not needed since BasicAuth is performed as part of the PEP
	proxies.PdpClientPool = proxies.NewClientPool(env.Config.Pdp.PdpClientPoolSize, env.Config.Pdp.X509KeyPairShownByPepToPdp)
	proxies.SfpLogicClientPool = proxies.NewClientPool(env.Config.SfpLogic.SfplClientPoolSize, env.Config.SfpLogic.X509KeyPairShownByPepToSfpl)
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
