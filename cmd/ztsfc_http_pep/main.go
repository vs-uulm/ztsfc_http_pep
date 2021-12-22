package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	confInit "github.com/vs-uulm/ztsfc_http_pep/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/router"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/yaml"
)

var (
	confFilePath string
	sysLogger    *logger.Logger
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "", "Path to user defined YML config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = yaml.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatal(err)
	}

	// Create an instance of the system logger
	confInit.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		log.Fatal(err)
	}
	confInit.SetupCloseHandler(sysLogger)
	sysLogger.Debugf("main: init(): loading logger configuration from '%s' - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the PEP
	config.Config.CAcertPoolPepAcceptsFromExt = x509.NewCertPool()
	config.Config.CAcertPoolPepAcceptsFromInt = x509.NewCertPool()

	// Preload diverse parameters from config
	// (One function for each section in config.yml)
	confInit.InitDefaultValues(sysLogger)

	// pep
	err = confInit.InitPepParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// Init BasicAuth, session, JWT certs
	err = confInit.InitBasicAuth(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// ldap
	err = confInit.InitLdapParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// pdp
	err = confInit.InitPdpParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// sfp_logic
	err = confInit.InitSfplParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// service_pool
	err = confInit.InitServicePoolParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

	// sf_pool
	err = confInit.InitSfPoolParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

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

	// Create a new PEP router
	pep, err := router.New(sysLogger)
	if err != nil {
		sysLogger.Fatalf("main: main(): unable to create a new router: %w", err)
	}
	sysLogger.Debug("main: main(): new router was successfully created")

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: main(): ListenAndServeTLS() fatal error: %w", err)
	}
}
