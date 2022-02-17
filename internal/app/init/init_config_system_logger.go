// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitSysLoggerParams() sets default values for the system logger parameters
// The function should be called before the system logger creation!
func InitSysLoggerParams() {
	// Set a default value of a logging level parameter
	if config.Config.SysLogger.LogLevel == "" {
		config.Config.SysLogger.LogLevel = "info"
	}

	// Set a default value of a log messages destination parameter
	if config.Config.SysLogger.LogFilePath == "" {
		config.Config.SysLogger.LogFilePath = "stdout"
	}

	// Set a default value of a log messages formatter parameter
	if config.Config.SysLogger.IfTextFormatter == "" {
		config.Config.SysLogger.IfTextFormatter = "json"
	}
}
