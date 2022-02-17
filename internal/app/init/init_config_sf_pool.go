// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"net/url"
	"strings"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitSfPoolParams() initializes the 'sf_pool' section of the config file and
// loads the certificates for the given file paths and preparses the URLs.
func initSfPool(sysLogger *logger.Logger) error {
	var err error

	if config.Config.SfPool == nil {
		sysLogger.Info("initSfPool(): the section 'sf_pool' is empty. No SF is defined")
	}

	for sfName, sfConfig := range config.Config.SfPool {
		fields := ""

		// This case is TRUE if a SF section such as logger is completely empty; in this case sfConfig is a nil pointer
		if sfConfig == nil {
			fields += "target_sf_addr,cert_shown_by_pep_to_sf,privkey_for_cert_shown_by_pep_to_sf,cert_pep_accepts_shown_by_sf"
			return fmt.Errorf("init: InitSfPoolParams(): in the section '%s' the following required fields are missed: '%s'",
				sfName, strings.TrimSuffix(fields, ","))
		}

		// Checking the yaml parameter if they are present and meaningful
		// TODO: Check if the field make sense as well!
		if sfConfig.TargetSfAddr == "" {
			fields += "target_sf_addr,"
		}

		// TODO: Check if the field make sense as well!
		if sfConfig.CertShownByPepToSf == "" {
			fields += "cert_shown_by_pep_to_sf,"
		}

		// TODO: Check if the field make sense as well!
		if sfConfig.PrivkeyForCertShownByPepToSf == "" {
			fields += "privkey_for_cert_shown_by_pep_to_sf,"
		}

		// TODO: Check if the field make sense as well!
		if sfConfig.CertPepAcceptsShownBySf == "" {
			fields += "cert_pep_accepts_shown_by_sf,"
		}

		if fields != "" {
			return fmt.Errorf("initSfPool(): in the section '%s' the following required fields are missed: '%s'",
				sfName, strings.TrimSuffix(fields, ","))
		}

		// preload X509KeyPairs shown by pep to sf
		config.Config.SfPool[sfName].X509KeyPairShownByPepToSf, err = loadX509KeyPair(sysLogger, sfConfig.CertShownByPepToSf, sfConfig.PrivkeyForCertShownByPepToSf, "service function "+sfName, "")
		if err != nil {
			return err
		}

		// Preparse SF URL
		config.Config.SfPool[sfName].TargetSfUrl, err = url.Parse(sfConfig.TargetSfAddr)
		if err != nil {
			return fmt.Errorf("initSfPool(): unable to parse a target service URL for service function '%s': %w", sfName, err)
		}
		sysLogger.Debugf("initSfPool(): Target URL for service function %s was successfully parsed", sfName)

		// Preload CA certificate and append it to cert pool
		err = loadCACertificate(sysLogger, sfConfig.CertPepAcceptsShownBySf, "service function "+sfName, config.Config.CAcertPoolPepAcceptsFromInt)
		if err != nil {
			return err
		}
	}

	return nil
}
