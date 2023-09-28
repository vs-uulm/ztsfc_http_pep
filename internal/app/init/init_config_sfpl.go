// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	gct "github.com/leobrada/golang_convenience_tools"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitSfplParams() initializes the 'sfp_logic' section of the config file and
// loads certificates for the given file paths.
func initSfpl(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	// TODO: Check if the field make sense as well!
	if config.Config.SfpLogic.TargetSfplAddr == "" {
		fields += "target_sfpl_addr,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.SfpLogic.CertShownByPepToSfpl == "" {
		fields += "cert_shown_by_pep_to_sfpl,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.SfpLogic.PrivkeyForCertShownByPepToSfpl == "" {
		fields += "privkey_for_cert_shown_by_pep_to_sfpl,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.SfpLogic.CertPepAcceptsShownBySfpl == "" {
		fields += "cert_pep_accepts_shown_by_sfpl,"
	}

	if fields != "" {
		return fmt.Errorf("initSfpl(): in the section 'sfp_logic' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Preload X509KeyPair and write it to config
	config.Config.SfpLogic.X509KeyPairShownByPepToSfpl, err = gct.LoadX509KeyPair(config.Config.SfpLogic.CertShownByPepToSfpl,
		config.Config.SfpLogic.PrivkeyForCertShownByPepToSfpl)
	if err != nil {
		return err
	}

	// Preload CA certificate and append it to cert pool
	err = gct.LoadCACertificate(config.Config.SfpLogic.CertPepAcceptsShownBySfpl, config.Config.CAcertPoolPepAcceptsFromInt)
	if err != nil {
		return err
	}

	// Use default pool size as sfpl pool size if necessary
	if config.Config.SfpLogic.SfplClientPoolSize == 0 {
		config.Config.SfpLogic.SfplClientPoolSize = config.Config.Pep.DefaultPoolSize
		sysLogger.Debugf("initSfpl(): SFPL client pool size is set to default pool size (%d)", config.Config.Pep.DefaultPoolSize)
	}

	return nil
}
