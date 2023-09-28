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

// InitPdpParams() initializes the 'pdp' section of the config file and
// loads certificates for the given file paths.
func initPdp(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	// TODO: Check if the field make sense as well!
	if config.Config.Pdp.TargetPdpAddr == "" {
		fields += "target_pdp_addr,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Pdp.CertShownByPepToPdp == "" {
		fields += "cert_shown_by_pep_to_pdp,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Pdp.PrivkeyForCertShownByPepToPdp == "" {
		fields += "privkey_for_cert_shown_by_pep_to_pdp,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Pdp.CertPepAcceptsShownByPdp == "" {
		fields += "cert_pep_accepts_shown_by_pdp,"
	}

	if fields != "" {
		return fmt.Errorf("init: InitPdpParams(): in the section 'pdp' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Preload X509KeyPair and write it to config
	config.Config.Pdp.X509KeyPairShownByPepToPdp, err = gct.LoadX509KeyPair(config.Config.Pdp.CertShownByPepToPdp, config.Config.Pdp.PrivkeyForCertShownByPepToPdp)
	if err != nil {
		return err
	}

	// Preload CA certificate and append it to cert pool
	err = gct.LoadCACertificate(config.Config.Pdp.CertPepAcceptsShownByPdp, config.Config.CAcertPoolPepAcceptsFromInt)
	if err != nil {
		return err
	}

	// Use default pool size as pdp pool size if necessary
	if config.Config.Pdp.PdpClientPoolSize == 0 {
		config.Config.Pdp.PdpClientPoolSize = config.Config.Pep.DefaultPoolSize
		sysLogger.Debugf("init: InitPdpParams(): PDP client pool size is set to default pool size (%d)", config.Config.Pep.DefaultPoolSize)
	}

	return nil
}
