package main

import (
	"crypto/x509"
	"flag"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	confInit "github.com/vs-uulm/ztsfc_http_pep/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/router"
)

var (
	confFilePath string
	sysLogger    *logwriter.LogWriter
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "", "Path to user defined yml config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = config.LoadConfig(confFilePath)
	if err != nil {
		return
	}

	// Create an instance of the system logger
	sysLogger, err = logwriter.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logrus.Fields{"type": "system"},
	)
	if err != nil {
		return
	}
	sysLogger.Debugf("loading logger configuration from %s - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the PEP
	config.Config.CAcertPoolPepAcceptsFromExt = x509.NewCertPool()
	config.Config.CAcertPoolPepAcceptsFromInt = x509.NewCertPool()

	// Preload diverse parameters from config
	// (One function for each section in config.yml)
	confInit.InitDefaultValues(sysLogger)
	confInit.InitSysLoggerParams(sysLogger)
	confInit.InitPepParams(sysLogger)
	confInit.InitBasicAuth(sysLogger)
	confInit.InitLdapParams(sysLogger)
	confInit.InitPdpParams(sysLogger)
	confInit.InitSfplParams(sysLogger)
	confInit.InitServicePoolParams(sysLogger)
	confInit.InitSfPoolParams(sysLogger)

	// Init Reverse Proxies used for the modules
	// Basic_auth_proxy currently not needed since BasicAuth is performed as part of the PEP
	proxies.PdpClientPool = proxies.NewClientPool(config.Config.Pdp.PdpClientPoolSize, config.Config.Pdp.X509KeyPairShownByPepToPdp)
	proxies.SfpLogicClientPool = proxies.NewClientPool(config.Config.SfpLogic.SfplClientPoolSize, config.Config.SfpLogic.X509KeyPairShownByPepToSfpl)
}

func main() {

	// Code snippets useful for performance profiling:
	// defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	// defer profile.Start(profile.BlockProfile, profile.ProfilePath(".")).Stop()
	// defer profile.Start(profile.GoroutineProfile, profile.ProfilePath(".")).Stop()

	// Create new PEP router
	pep, err := router.NewRouter()
	if err != nil {
		sysLogger.Fatalf("unable to create a new router: %s", err.Error())
	}
	sysLogger.Debug("new router is successfully created")

	pep.SetLogWriter(sysLogger)

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("ListenAndServeTLS() Fatal Error: %s", err.Error())
	}
}
