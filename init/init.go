// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/url"

	"github.com/sirupsen/logrus"
	env "local.com/leobrada/ztsfc_http_pep/env"
)

// Function initializes the 'pep' section of the config file.
// It loads the PEP certificate.
func InitPepParams(sysLogger *logrus.Entry) {

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range env.Config.Pep.CertsPepAcceptsWhenShownByClients {
		loadCACertificate(sysLogger, acceptedClientCert, "client", env.Config.CAcertPoolPepAcceptsFromExt)
	}
}

// Function initializes the 'ldap' section of the config file.
// Function currently does nothing.
func InitLdapParams(sysLogger *logrus.Entry) {

}

// Function initializes the 'pdp' section of the config file.
// It loads the certificates for the given file paths.
func InitPdpParams(sysLogger *logrus.Entry) {

	// Preload X509KeyPair and write it to env
	env.Config.Pdp.X509KeyPairShownByPepToPdp = loadX509KeyPair(sysLogger, env.Config.Pdp.CertShownByPepToPdp, env.Config.Pdp.PrivkeyForCertShownByPepToPdp, "PDP", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.Pdp.CertPepAcceptsShownByPdp, "PDP", env.Config.CAcertPoolPepAcceptsFromInt)

	// Use default pool size as pdp pool size if necessary
	// @author:marie
	if env.Config.Pdp.PdpClientPoolSize == 0 {
		if env.Config.Pep.DefaultPoolSize != 0 {
			env.Config.Pdp.PdpClientPoolSize = env.Config.Pep.DefaultPoolSize
			sysLogger.Debugf("pdp client pool size set to default pool size (%d)", env.Config.Pep.DefaultPoolSize)
		} else {
			sysLogger.Fatalf("config provides neither a pdp_client_pool_size nor a default_pool_size")
		}
	}
}

// Function initializes the 'sfp_logic' section of the config file.
// It loads the certificates for the given file paths.
func InitSfplParams(sysLogger *logrus.Entry) {

	// Preload X509KeyPair and write it to env
	env.Config.SfpLogic.X509KeyPairShownByPepToSfpl = loadX509KeyPair(sysLogger, env.Config.SfpLogic.CertShownByPepToSfpl, env.Config.SfpLogic.PrivkeyForCertShownByPepToSfpl, "SFP_logic", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.SfpLogic.CertPepAcceptsShownBySfpl, "SFP_logic", env.Config.CAcertPoolPepAcceptsFromInt)

	// Use default pool size as sfpl pool size if necessary
	// @author:marie
	if env.Config.SfpLogic.SfplClientPoolSize == 0 {
		if env.Config.Pep.DefaultPoolSize != 0 {
			env.Config.SfpLogic.SfplClientPoolSize = env.Config.Pep.DefaultPoolSize
			sysLogger.Debugf("sfpl client pool size set to default pool size (%d)", env.Config.Pep.DefaultPoolSize)
		} else {
			sysLogger.Fatalf("config provides neither an sfpl_client_pool_size nor a default_pool_size")
		}
	}
}

// Function initializes the 'service_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
// Additionally, it creates a map to access services by SNI directly.
func InitServicePoolParams(sysLogger *logrus.Entry) {
	var err error
	for serviceName, serviceConfig := range env.Config.ServicePool {

		// Preload X509KeyPairs shown by pep to client
		env.Config.ServicePool[serviceName].X509KeyPairShownByPepToClient = loadX509KeyPair(sysLogger, serviceConfig.CertShownByPepToClientsMatchingSni, serviceConfig.PrivkeyForCertShownByPepToClient, "service "+serviceName, "external")

		// Preload X509KeyPairs shown by pep to service
		env.Config.ServicePool[serviceName].X509KeyPairShownByPepToService = loadX509KeyPair(sysLogger, serviceConfig.CertShownByPepToService, serviceConfig.PrivkeyForCertShownByPepToService, "service "+serviceName, "internal")

		// Preparse Service URL
		env.Config.ServicePool[serviceName].TargetServiceUrl, err = url.Parse(serviceConfig.TargetServiceAddr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target service URL for service %s: %v", serviceName, err)
		} else {
			sysLogger.Debugf("target service URL for service %s was successfully parsed", serviceName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, serviceConfig.CertPepAcceptsWhenShownByService, "service "+serviceName, env.Config.CAcertPoolPepAcceptsFromInt)

		// Create a map to directly access service config by SNI
		// @author:marie
		env.Config.ServiceSniMap = make(map[string]*env.ServiceT)
		for _, service := range env.Config.ServicePool {
			env.Config.ServiceSniMap[service.Sni] = service
		}
	}
}

// Function initializes the 'sf_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
func InitSfPoolParams(sysLogger *logrus.Entry) {
	var err error
	for sfName, sfConfig := range env.Config.SfPool {

		// preload X509KeyPairs shown by pep to sf
		env.Config.SfPool[sfName].X509KeyPairShownByPepToSf = loadX509KeyPair(sysLogger, sfConfig.CertShownByPepToSf, sfConfig.PrivkeyForCertShownByPepToSf, "service function "+sfName, "")

		// Preparse SF URL
		env.Config.SfPool[sfName].TargetSfUrl, err = url.Parse(sfConfig.TargetSfAddr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target URL for service function %s: %v", sfName, err)
		} else {
			sysLogger.Debugf("Target URL for service function %s was successfully parsed", sfName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, sfConfig.CertPepAcceptsShownBySf, "service function "+sfName, env.Config.CAcertPoolPepAcceptsFromInt)
	}
}

// function unifies the loading of X509 key pairs for different components
// @author:marie
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
// @author:marie
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
