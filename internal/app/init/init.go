// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

func InitDefaultValues(sysLogger *logrus.Entry) {

	// Initialize a DefaultPoolSize if its not set
	if config.Config.Pep.DefaultPoolSize == 0 {
		config.Config.Pep.DefaultPoolSize = 50
	}

}

// Function initializes the 'pep' section of the config file.
// It loads the PEP certificate.
func InitPepParams(sysLogger *logrus.Entry) {
	section := "pep"
	fields := ""

	// TODO: Check if the field make sense as well!
	if config.Config.Pep.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if config.Config.Pep.CertsPepAcceptsWhenShownByClients == nil {
		fields += "certs_pep_accepts_when_shown_by_clients,"
	}

	if fields != "" {
		fields = strings.TrimSuffix(fields, ",")
		handleFatalf(sysLogger, section, fields)
	}

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range config.Config.Pep.CertsPepAcceptsWhenShownByClients {
		loadCACertificate(sysLogger, acceptedClientCert, "client", config.Config.CAcertPoolPepAcceptsFromExt)
	}
}

func InitBasicAuth(sysLogger *logrus.Entry) {
	initSession(sysLogger)
}

func initSession(sysLogger *logrus.Entry) {
	section := "session"
	fields := ""

	if config.Config.BasicAuth.Session.Path_to_jwt_pub_key == "" {
		fields += "path_to_jwt_pub_key,"
	} else {
		sysLogger.Debugf("JWT Public Key is searched for here: %s", config.Config.BasicAuth.Session.Path_to_jwt_pub_key)
	}

	if config.Config.BasicAuth.Session.Path_to_jwt_signing_key == "" {
		fields += "path_to_jwt_signing_key,"
	} else {
		sysLogger.Debugf("JWT Signing Key is searched for here: %s", config.Config.BasicAuth.Session.Path_to_jwt_signing_key)
	}

	if fields != "" {
		fields = strings.TrimSuffix(fields, ",")
		handleFatalf(sysLogger, section, fields)
	}

	config.Config.BasicAuth.Session.JwtPubKey = basic_auth.ParseRsaPublicKeyFromPemStr(sysLogger, config.Config.BasicAuth.Session.Path_to_jwt_pub_key)
	config.Config.BasicAuth.Session.MySigningKey = basic_auth.ParseRsaPrivateKeyFromPemStr(sysLogger, config.Config.BasicAuth.Session.Path_to_jwt_signing_key)
}

// Function initializes the 'ldap' section of the config file.
// Function currently does nothing.
func InitLdapParams(sysLogger *logrus.Entry) {

}

// Function initializes the 'pdp' section of the config file.
// It loads the certificates for the given file paths.
func InitPdpParams(sysLogger *logrus.Entry) {
	section := "pdp"
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
		fields = strings.TrimSuffix(fields, ",")
		handleFatalf(sysLogger, section, fields)
	}

	// Preload X509KeyPair and write it to env
	config.Config.Pdp.X509KeyPairShownByPepToPdp = loadX509KeyPair(sysLogger, config.Config.Pdp.CertShownByPepToPdp, config.Config.Pdp.PrivkeyForCertShownByPepToPdp, "PDP", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, config.Config.Pdp.CertPepAcceptsShownByPdp, "PDP", config.Config.CAcertPoolPepAcceptsFromInt)

	// Use default pool size as pdp pool size if necessary
	if config.Config.Pdp.PdpClientPoolSize == 0 {
		config.Config.Pdp.PdpClientPoolSize = config.Config.Pep.DefaultPoolSize
		sysLogger.Debugf("PDP client pool size set to default pool size (%d)", config.Config.Pep.DefaultPoolSize)
	}
}

// Function initializes the 'sfp_logic' section of the config file.
// It loads the certificates for the given file paths.
func InitSfplParams(sysLogger *logrus.Entry) {
	section := "sfp_logic"
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
		fields = strings.TrimSuffix(fields, ",")
		handleFatalf(sysLogger, section, fields)
	}

	// Preload X509KeyPair and write it to env
	config.Config.SfpLogic.X509KeyPairShownByPepToSfpl = loadX509KeyPair(sysLogger, config.Config.SfpLogic.CertShownByPepToSfpl, config.Config.SfpLogic.PrivkeyForCertShownByPepToSfpl, "SFP_logic", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, config.Config.SfpLogic.CertPepAcceptsShownBySfpl, "SFP_logic", config.Config.CAcertPoolPepAcceptsFromInt)

	// Use default pool size as sfpl pool size if necessary
	if config.Config.SfpLogic.SfplClientPoolSize == 0 {
		config.Config.SfpLogic.SfplClientPoolSize = config.Config.Pep.DefaultPoolSize
		sysLogger.Debugf("SFPL client pool size set to default pool size (%d)", config.Config.Pep.DefaultPoolSize)
	}
}

// Function initializes the 'service_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
// Additionally, it creates a map to access services by SNI directly.
func InitServicePoolParams(sysLogger *logrus.Entry) {
	var err error

	if config.Config.ServicePool == nil {
		sysLogger.Fatalf("Service Pool field 'service_pool' is empty. No Service is defined")
	}

	for serviceName, serviceConfig := range config.Config.ServicePool {
		fields := ""

		if serviceConfig == nil {
			fields += "sni,target_service_addr,privkey_for_cert_shown_by_pep_to_clients_matching_sni,privkey_for_cert_shown_by_pep_to_client," +
				"cert_shown_by_pep_to_service,privkey_for_cert_shown_by_pep_to_service,cert_pep_accepts_when_shown_by_service"
			handleFatalf(sysLogger, serviceName, fields)
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
			fields = strings.TrimSuffix(fields, ",")
			handleFatalf(sysLogger, serviceName, fields)
		}

		// Preload X509KeyPairs shown by pep to client
		config.Config.ServicePool[serviceName].X509KeyPairShownByPepToClient = loadX509KeyPair(sysLogger, serviceConfig.CertShownByPepToClientsMatchingSni, serviceConfig.PrivkeyForCertShownByPepToClient, "service "+serviceName, "external")

		// Preload X509KeyPairs shown by pep to service
		config.Config.ServicePool[serviceName].X509KeyPairShownByPepToService = loadX509KeyPair(sysLogger, serviceConfig.CertShownByPepToService, serviceConfig.PrivkeyForCertShownByPepToService, "service "+serviceName, "internal")

		// Preparse Service URL
		config.Config.ServicePool[serviceName].TargetServiceUrl, err = url.Parse(serviceConfig.TargetServiceAddr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target service URL for service %s: %v", serviceName, err)
		} else {
			sysLogger.Debugf("Target service URL for service %s was successfully parsed", serviceName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, serviceConfig.CertPepAcceptsWhenShownByService, "service "+serviceName, config.Config.CAcertPoolPepAcceptsFromInt)

		// Create a map to directly access service config by SNI
		config.Config.ServiceSniMap = make(map[string]*config.ServiceT)
		for _, service := range config.Config.ServicePool {
			config.Config.ServiceSniMap[service.Sni] = service
		}
	}
}

// Function initializes the 'sf_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
func InitSfPoolParams(sysLogger *logrus.Entry) {
	var err error

	if config.Config.SfPool == nil {
		sysLogger.Debugf("Service Pool field 'sf_pool' is empty. No SF is defined")
	}

	for sfName, sfConfig := range config.Config.SfPool {
		fields := ""

		// This case is TRUE if a SF section such as logger is completely empty; in this case sfConfig is a nil pointer
		if sfConfig == nil {
			fields += "target_sf_addr,cert_shown_by_pep_to_sf,privkey_for_cert_shown_by_pep_to_sf,cert_pep_accepts_shown_by_sf"
			handleFatalf(sysLogger, sfName, fields)
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
			fields = strings.TrimSuffix(fields, ",")
			handleFatalf(sysLogger, sfName, fields)
		}

		// preload X509KeyPairs shown by pep to sf
		config.Config.SfPool[sfName].X509KeyPairShownByPepToSf = loadX509KeyPair(sysLogger, sfConfig.CertShownByPepToSf, sfConfig.PrivkeyForCertShownByPepToSf, "service function "+sfName, "")

		// Preparse SF URL
		config.Config.SfPool[sfName].TargetSfUrl, err = url.Parse(sfConfig.TargetSfAddr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target URL for service function %s: %v", sfName, err)
		} else {
			sysLogger.Debugf("Target URL for service function %s was successfully parsed", sfName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, sfConfig.CertPepAcceptsShownBySf, "service function "+sfName, config.Config.CAcertPoolPepAcceptsFromInt)
	}
}

// function unifies the loading of X509 key pairs for different components
func loadX509KeyPair(sysLogger *logrus.Entry, certfile, keyfile, componentName, certAttr string) tls.Certificate {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		sysLogger.Fatalf("Critical Error when loading %s X509KeyPair for %s from %s and %s: %v", certAttr, componentName, certfile, keyfile, err)
	} else {
		sysLogger.Debugf("%s X509KeyPair for %s from %s and %s is successfully loaded", certAttr, componentName, certfile, keyfile)
	}
	return keyPair
}

// function unifies the loading of CA certificates for different components
func loadCACertificate(sysLogger *logrus.Entry, certfile string, componentName string, certPool *x509.CertPool) {
	caRoot, err := ioutil.ReadFile(certfile)
	if err != nil {
		sysLogger.Fatalf("Loading %s CA certificate from %s error: %v", componentName, certfile, err)
	} else {
		sysLogger.Debugf("%s CA certificate from %s is successfully loaded", componentName, certfile)
	}
	// Append a certificate to the pool
	certPool.AppendCertsFromPEM(caRoot)
}

func handleFatalf(sysLogger *logrus.Entry, section, fields string) {
	sysLogger.Fatalf("For section '%s' the necessary field(s) '%s' is/are not present.", section, fields)
}
