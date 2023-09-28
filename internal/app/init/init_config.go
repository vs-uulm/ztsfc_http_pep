// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"fmt"

	logger "github.com/vs-uulm/ztsfc_http_logger"
)

func InitConfig(sysLogger *logger.Logger) error {
	initDefaultValues(sysLogger)

	if err := initBlocklists(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initPep(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initBasicAuth(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initPdp(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initPip(); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initSfpl(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initServicePool(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initSfPool(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	return nil
}
