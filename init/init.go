// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yaml corresponds to a function of this package.
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
	for _, acceptedClientCert := range env.Config.Pep.Certs_pep_accepts_when_shown_by_clients {
		loadCACertificate(sysLogger, acceptedClientCert, "client", env.Config.CA_cert_pool_pep_accepts_from_ext)
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
	env.Config.Pdp.X509KeyPair_shown_by_pep_to_pdp = loadX509KeyPair(sysLogger, env.Config.Pdp.Cert_shown_by_pep_to_pdp, env.Config.Pdp.Privkey_for_cert_shown_by_pep_to_pdp, "PDP", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.Pdp.Cert_pep_accepts_shown_by_pdp, "PDP", env.Config.CA_cert_pool_pep_accepts_from_int)

	// Use default pool size as pdp pool size if necessary
	// @author:marie
	if env.Config.Pdp.Pdp_client_pool_size == 0 {
		if env.Config.Pep.Default_pool_size != 0 {
			env.Config.Pdp.Pdp_client_pool_size = env.Config.Pep.Default_pool_size
			sysLogger.Debugf("pdp client pool size set to default pool size (%d)", env.Config.Pep.Default_pool_size)
		} else {
			sysLogger.Fatalf("config provides neither a pdp_client_pool_size nor a default_pool_size")
		}
	}
}

// Function initializes the 'sfp_logic' section of the config file.
// It loads the certificates for the given file paths.
func InitSfplParams(sysLogger *logrus.Entry) {

	// Preload X509KeyPair and write it to env
	env.Config.Sfp_logic.X509KeyPair_shown_by_pep_to_sfpl = loadX509KeyPair(sysLogger, env.Config.Sfp_logic.Cert_shown_by_pep_to_sfpl, env.Config.Sfp_logic.Privkey_for_cert_shown_by_pep_to_sfpl, "SFP_logic", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.Sfp_logic.Cert_pep_accepts_shown_by_sfpl, "SFP_logic", env.Config.CA_cert_pool_pep_accepts_from_int)

	// Use default pool size as sfpl pool size if necessary
	// @author:marie
	if env.Config.Sfp_logic.Sfpl_client_pool_size == 0 {
		if env.Config.Pep.Default_pool_size != 0 {
			env.Config.Sfp_logic.Sfpl_client_pool_size = env.Config.Pep.Default_pool_size
			sysLogger.Debugf("sfpl client pool size set to default pool size (%d)", env.Config.Pep.Default_pool_size)
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
	for serviceName, serviceConfig := range env.Config.Service_pool {

		// Preload X509KeyPairs shown by pep to client
		env.Config.Service_pool[serviceName].X509KeyPair_shown_by_pep_to_client = loadX509KeyPair(sysLogger, serviceConfig.Cert_shown_by_pep_to_clients_matching_sni, serviceConfig.Privkey_for_cert_shown_by_pep_to_client, "service "+serviceName, "external")

		// Preload X509KeyPairs shown by pep to service
		env.Config.Service_pool[serviceName].X509KeyPair_shown_by_pep_to_service = loadX509KeyPair(sysLogger, serviceConfig.Cert_shown_by_pep_to_service, serviceConfig.Privkey_for_cert_shown_by_pep_to_service, "service "+serviceName, "internal")

		// Preparse Service URL
		env.Config.Service_pool[serviceName].Target_service_url, err = url.Parse(serviceConfig.Target_service_addr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target service URL for service %s: %v", serviceName, err)
		} else {
			sysLogger.Debugf("target service URL for service %s was successfully parsed", serviceName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, serviceConfig.Cert_pep_accepts_when_shown_by_service, "service "+serviceName, env.Config.CA_cert_pool_pep_accepts_from_int)

		// Create a map to directly access service config by SNI
		// @author:marie
		env.Config.Service_SNI_map = make(map[string]*env.Service_t)
		for _, service := range env.Config.Service_pool {
			env.Config.Service_SNI_map[service.Sni] = service
		}
	}
}

// Function initializes the 'sf_pool' section of the config file.
// It loads the certificates for the given file paths and preparses the URLs.
func InitSfPoolParams(sysLogger *logrus.Entry) {
	var err error
	for sfName, sfConfig := range env.Config.Sf_pool {

		// preload X509KeyPairs shown by pep to sf
		env.Config.Sf_pool[sfName].X509KeyPair_shown_by_pep_to_sf = loadX509KeyPair(sysLogger, sfConfig.Cert_shown_by_pep_to_sf, sfConfig.Privkey_for_cert_shown_by_pep_to_sf, "service function "+sfName, "")

		// Preparse SF URL
		env.Config.Sf_pool[sfName].Target_sf_url, err = url.Parse(sfConfig.Target_sf_addr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target URL for service function %s: %v", sfName, err)
		} else {
			sysLogger.Debugf("Target URL for service function %s was successfully parsed", sfName)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, sfConfig.Cert_pep_accepts_shown_by_sf, "service function "+sfName, env.Config.CA_cert_pool_pep_accepts_from_int)
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
