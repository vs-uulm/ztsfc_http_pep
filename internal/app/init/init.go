// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitDefaultValues() sets a default PEP DefaultPoolSize value
func InitDefaultValues(sysLogger *logger.Logger) {
	// Initialize a DefaultPoolSize if its not set
	if config.Config.Pep.DefaultPoolSize == 0 {
		config.Config.Pep.DefaultPoolSize = 50
	}
	sysLogger.Debug("init: InitDefaultValues(): Config.Pep.DefaultPoolSize is set to 50")
}

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

// InitPepParams() initializes the 'pep' section of the config file and
// loads the PEP certificate(s).
func InitPepParams(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	// TODO: Check if the field make sense as well!
	if config.Config.Pep.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if config.Config.Pep.CertsPepAcceptsWhenShownByClients == nil {
		fields += "certs_pep_accepts_when_shown_by_clients,"
	}

	if fields != "" {
		return fmt.Errorf("init: InitPepParams(): in the section 'pep' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range config.Config.Pep.CertsPepAcceptsWhenShownByClients {
		err = loadCACertificate(sysLogger, acceptedClientCert, "client", config.Config.CAcertPoolPepAcceptsFromExt)
		if err != nil {
			return err
		}
	}

	return nil
}

// InitBasicAuth() ...
func InitBasicAuth(sysLogger *logger.Logger) error {
	return initSession(sysLogger)
}

// InitSession() ...
func initSession(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	if config.Config.BasicAuth.Session.Path_to_jwt_pub_key == "" {
		fields += "path_to_jwt_pub_key,"
	}
	sysLogger.Debugf("init: initSession(): JWT Public Key path: '%s'", config.Config.BasicAuth.Session.Path_to_jwt_pub_key)

	if config.Config.BasicAuth.Session.Path_to_jwt_signing_key == "" {
		fields += "path_to_jwt_signing_key,"
	}
	sysLogger.Debugf("init: initSession(): JWT Signing Key path: '%s'", config.Config.BasicAuth.Session.Path_to_jwt_signing_key)

	if fields != "" {
		return fmt.Errorf("init: initSession(): in the section 'session' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	config.Config.BasicAuth.Session.JwtPubKey, err = basic_auth.ParseRsaPublicKeyFromPemStr(config.Config.BasicAuth.Session.Path_to_jwt_pub_key)
	if err != nil {
		return err
	}

	config.Config.BasicAuth.Session.MySigningKey, err = basic_auth.ParseRsaPrivateKeyFromPemStr(config.Config.BasicAuth.Session.Path_to_jwt_signing_key)
	if err != nil {
		return err
	}

	return nil
}

// InitLdapParams() initializes the 'ldap' section of the config file.
// Function currently does nothing.
func InitLdapParams(sysLogger *logger.Logger) error {
	return nil
}

// InitPdpParams() initializes the 'pdp' section of the config file and
// loads certificates for the given file paths.
func InitPdpParams(sysLogger *logger.Logger) error {
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
	config.Config.Pdp.X509KeyPairShownByPepToPdp, err = loadX509KeyPair(sysLogger, config.Config.Pdp.CertShownByPepToPdp, config.Config.Pdp.PrivkeyForCertShownByPepToPdp, "PDP", "")
	if err != nil {
		return err
	}

	// Preload CA certificate and append it to cert pool
	err = loadCACertificate(sysLogger, config.Config.Pdp.CertPepAcceptsShownByPdp, "PDP", config.Config.CAcertPoolPepAcceptsFromInt)
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

// InitSfplParams() initializes the 'sfp_logic' section of the config file and
// loads certificates for the given file paths.
func InitSfplParams(sysLogger *logger.Logger) error {
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
		return fmt.Errorf("init: InitSfplParams(): in the section 'sfp_logic' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Preload X509KeyPair and write it to config
	config.Config.SfpLogic.X509KeyPairShownByPepToSfpl, err = loadX509KeyPair(sysLogger, config.Config.SfpLogic.CertShownByPepToSfpl,
		config.Config.SfpLogic.PrivkeyForCertShownByPepToSfpl, "SFP_logic", "")
	if err != nil {
		return err
	}

	// Preload CA certificate and append it to cert pool
	err = loadCACertificate(sysLogger, config.Config.SfpLogic.CertPepAcceptsShownBySfpl, "SFP_logic", config.Config.CAcertPoolPepAcceptsFromInt)
	if err != nil {
		return err
	}

	// Use default pool size as sfpl pool size if necessary
	if config.Config.SfpLogic.SfplClientPoolSize == 0 {
		config.Config.SfpLogic.SfplClientPoolSize = config.Config.Pep.DefaultPoolSize
		sysLogger.Debugf("init: InitSfplParams(): SFPL client pool size is set to default pool size (%d)", config.Config.Pep.DefaultPoolSize)
	}

	return nil
}

// InitServicePoolParams() initializes the 'service_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
// Additionally, it creates a map to access services by SNI directly.
func InitServicePoolParams(sysLogger *logger.Logger) error {
	var err error

	if config.Config.ServicePool == nil {
		return errors.New("init: InitServicePoolParams(): the section 'service_pool' is empty. No Service is defined")
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
			return fmt.Errorf("init: InitServicePoolParams(): in the section '%s' the following required fields are missed: '%s'",
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
			return fmt.Errorf("init: InitServicePoolParams(): unable to parse a target service URL for service '%s': %w", serviceName, err)
		}
		sysLogger.Debugf("init: InitServicePoolParams(): Target service URL for service %s was successfully parsed", serviceName)

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

// InitSfPoolParams() initializes the 'sf_pool' section of the config file and
// loads the certificates for the given file paths and preparses the URLs.
func InitSfPoolParams(sysLogger *logger.Logger) error {
	var err error

	if config.Config.SfPool == nil {
		sysLogger.Info("init: InitSfPoolParams(): the section 'sf_pool' is empty. No SF is defined")
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
			return fmt.Errorf("init: InitSfPoolParams(): in the section '%s' the following required fields are missed: '%s'",
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
			return fmt.Errorf("init: InitServicePoolParams(): unable to parse a target service URL for service function '%s': %w", sfName, err)
		}
		sysLogger.Debugf("init: InitServicePoolParams(): Target URL for service function %s was successfully parsed", sfName)

		// Preload CA certificate and append it to cert pool
		err = loadCACertificate(sysLogger, sfConfig.CertPepAcceptsShownBySf, "service function "+sfName, config.Config.CAcertPoolPepAcceptsFromInt)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadX509KeyPair() unifies the loading of X509 key pairs for different components
func loadX509KeyPair(sysLogger *logger.Logger, certfile, keyfile, componentName, certAttr string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: loadX509KeyPair(): loading %s X509KeyPair for %s from %s and %s - FAIL: %v",
			certAttr, componentName, certfile, keyfile, err)
	}
	sysLogger.Debugf("init: loadX509KeyPair(): loading %s X509KeyPair for %s from %s and %s - OK", certAttr, componentName, certfile, keyfile)
	return keyPair, nil
}

// function unifies the loading of CA certificates for different components
func loadCACertificate(sysLogger *logger.Logger, certfile string, componentName string, certPool *x509.CertPool) error {
	// Read the certificate file content
	caRoot, err := ioutil.ReadFile(certfile)
	if err != nil {
		return fmt.Errorf("init: loadCACertificate(): loading %s CA certificate from '%s' - FAIL: %w", componentName, certfile, err)
	}
	sysLogger.Debugf("init: loadCACertificate(): loading %s CA certificate from '%s' - OK", componentName, certfile)

	// ToDo: check if certPool exists
	// if certPool == ??? {}
	//     return errors.New("provided certPool is nil")
	// }

	// Append a certificate to the pool
	certPool.AppendCertsFromPEM(caRoot)
	return nil
}

func SetupCloseHandler(logger *logger.Logger) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Debug("- 'Ctrl + C' was pressed in the Terminal. Terminating...")
		logger.Terminate()
		os.Exit(0)
	}()
}
