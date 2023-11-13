package main

import (
	"flag"
	"log"
	"net/http"

	yt "github.com/leobrada/yaml_tools"
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
	// Operating input parameters
	flag.StringVar(&confFilePath, "c", "./config/conf.yml", "Path to user defined YML config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err := yt.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatalf("main: init(): could not load yaml file: %v", err)
	}

	// init System Logger
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

	if err = confInit.InitConfig(sysLogger); err != nil {
		sysLogger.Fatalf("main: init(): %v", err)
	}

	// Initializes Client Pools for PDP and SFP TLS connections
	proxies.PdpClientPool = proxies.NewClientPool(config.Config.Pdp.PdpClientPoolSize, config.Config.Pdp.X509KeyPairShownByPepToPdp)
	proxies.SfpLogicClientPool = proxies.NewClientPool(config.Config.SfpLogic.SfplClientPoolSize, config.Config.SfpLogic.X509KeyPairShownByPepToSfpl)

	sysLogger.Infof("main: init(): Initializing PEP from %s - OK", confFilePath)
}

func main() {
	// Create new PEP router
	pep, err := router.NewRouter(sysLogger)
	if err != nil {
		sysLogger.Fatalf("main: main(): unable to create a new router: %w", err)
	}
	sysLogger.Info("main: main(): new router was successfully created")

	http.Handle("/", pep)

	err = pep.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("main: main(): ListenAndServeTLS() fatal error: %w", err)
	}
}
