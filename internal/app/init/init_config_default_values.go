// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitDefaultValues() sets a default PEP DefaultPoolSize value
func initDefaultValues(sysLogger *logger.Logger) {
	// Initialize a DefaultPoolSize if its not set
	if config.Config.Pep.DefaultPoolSize == 0 {
		config.Config.Pep.DefaultPoolSize = 50
	}
	sysLogger.Debug("init: InitDefaultValues(): Config.Pep.DefaultPoolSize is set to 50")
}
