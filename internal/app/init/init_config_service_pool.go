// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"errors"
	"fmt"
	"strings"
    "net/url"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitServicePoolParams() initializes the 'service_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
// Additionally, it creates a map to access services by SNI directly.
func initServicePool(sysLogger *logger.Logger) error {
	var err error

	if config.Config.ServicePool == nil {
		return errors.New("initServicePool(): the section 'service_pool' is empty. No Service is defined")
	}

	for serviceName, serviceConfig := range config.Config.ServicePool {
		fields := ""

		if serviceConfig == nil {
			fields += "sni,target_service_addr,privkey_for_cert_shown_by_pep_to_clients_matching_sni,privkey_for_cert_shown_by_pep_to_client," +
				"cert_shown_by_pep_to_service,privkey_for_cert_shown_by_pep_to_service,cert_pep_accepts_when_shown_by_service"
			return fmt.Errorf("init: InitServicePoolParams(): in the section '%s' the following required fields are missed: '%s'",
				serviceName, strings.TrimSuffix(fields, ","))
		}

		// Checking the yaml parameter if they are present and meaningful
		// TODO: Check if the field make sense as well!
		if serviceConfig.Sni == "" {
			fields += "sni,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.TargetServiceAddr == "" {
			fields += "target_service_addr,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.CertShownByPepToClientsMatchingSni == "" {
			fields += "privkey_for_cert_shown_by_pep_to_clients_matching_sni,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.PrivkeyForCertShownByPepToClient == "" {
			fields += "privkey_for_cert_shown_by_pep_to_client,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.CertShownByPepToService == "" {
			fields += "cert_shown_by_pep_to_service,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.PrivkeyForCertShownByPepToService == "" {
			fields += "privkey_for_cert_shown_by_pep_to_service,"
		}

		// TODO: Check if the field make sense as well!
		if serviceConfig.CertPepAcceptsWhenShownByService == "" {
			fields += "cert_pep_accepts_when_shown_by_service,"
		}

		if fields != "" {
			return fmt.Errorf("initServicePool(): in the section '%s' the following required fields are missed: '%s'",
				serviceName, strings.TrimSuffix(fields, ","))
		}

		// Preload X509KeyPairs shown by pep to client
		config.Config.ServicePool[serviceName].X509KeyPairShownByPepToClient, err = loadX509KeyPair(sysLogger,
			serviceConfig.CertShownByPepToClientsMatchingSni, serviceConfig.PrivkeyForCertShownByPepToClient, "service "+serviceName, "external")
		if err != nil {
			return err
		}

		// Preload X509KeyPairs shown by pep to service
		config.Config.ServicePool[serviceName].X509KeyPairShownByPepToService, err = loadX509KeyPair(sysLogger,
			serviceConfig.CertShownByPepToService, serviceConfig.PrivkeyForCertShownByPepToService, "service "+serviceName, "internal")
		if err != nil {
			return err
		}

		// Preparse Service URL
		config.Config.ServicePool[serviceName].TargetServiceUrl, err = url.Parse(serviceConfig.TargetServiceAddr)
		if err != nil {
			return fmt.Errorf("initServicePool(): unable to parse a target service URL for service '%s': %w", serviceName, err)
		}
		sysLogger.Debugf("initServicePool(): Target service URL for service %s was successfully parsed", serviceName)

		// Preload CA certificate and append it to cert pool
		err = loadCACertificate(sysLogger, serviceConfig.CertPepAcceptsWhenShownByService, "service "+serviceName, config.Config.CAcertPoolPepAcceptsFromInt)
		if err != nil {
			return err
		}

		// Create a map to directly access service config by SNI
		config.Config.ServiceSniMap = make(map[string]*config.ServiceT)
		for _, service := range config.Config.ServicePool {
			config.Config.ServiceSniMap[service.Sni] = service
		}
	}

	return nil
}
