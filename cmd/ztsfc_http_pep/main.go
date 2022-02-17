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
)

var (
	confFilePath string
	sysLogger    *logger.Logger
)

func init() {
	var err error

	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined YML config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = config.LoadConfig(confFilePath)
	if err != nil {
		log.Fatal(err)
	}

    // init system logger
	confInit.InitSysLoggerParams()

	// Create an instance of the system logger
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		log.Fatal(err)
	}
	confInit.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from %s - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the PEP
	config.Config.CAcertPoolPepAcceptsFromExt = x509.NewCertPool()
	config.Config.CAcertPoolPepAcceptsFromInt = x509.NewCertPool()

    if err = confInit.InitConfig(sysLogger); err != nil {
        sysLogger.Fatalf("main: init(): %v", err)
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

	// Create new PEP router
	pep, err := router.NewRouter(sysLogger)
	if err != nil {
		sysLogger.Fatalf("main: unable to create a new router: %w", err)
	}
	sysLogger.Debug("main: new router was successfully created")

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: ListenAndServeTLS() fatal error: %w", err)
	}
}
