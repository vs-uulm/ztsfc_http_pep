// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yaml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	env "local.com/leobrada/ztsfc_http_pep/env"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
)

func InitPepParams(sysLogger *logrus.Entry) {

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range env.Config.Pep.Certs_pep_accepts_when_shown_by_clients {
		loadCACertificate(sysLogger, acceptedClientCert, "client", env.Config.CA_cert_pool_pep_accepts_from_ext)
	}
}

func InitLdapParams(sysLogger *logrus.Entry) {

}

func InitPdpParams(sysLogger *logrus.Entry) {

	// Preload X509KeyPair and write it to env
	env.Config.Pdp.X509KeyPair_shown_by_pep_to_pdp = loadX509KeyPair(sysLogger, env.Config.Pdp.Cert_shown_by_pep_to_pdp, env.Config.Pdp.Privkey_for_cert_shown_by_pep_to_pdp, "PDP", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.Pdp.Cert_pep_accepts_shown_by_pdp, "PDP", env.Config.CA_cert_pool_pep_accepts_from_int)
}

func InitSfplParams(sysLogger *logrus.Entry) {

	// Preload X509KeyPair and write it to env
	env.Config.Sfp_logic.X509KeyPair_shown_by_pep_to_sfpl = loadX509KeyPair(sysLogger, env.Config.Sfp_logic.Cert_shown_by_pep_to_sfpl, env.Config.Sfp_logic.Privkey_for_cert_shown_by_pep_to_sfpl, "SFP_logic", "")

	// Preload CA certificate and append it to cert pool
	loadCACertificate(sysLogger, env.Config.Sfp_logic.Cert_pep_accepts_shown_by_sfpl, "SFP_logic", env.Config.CA_cert_pool_pep_accepts_from_int)
}

func InitServicePoolParams(sysLogger *logrus.Entry) {
	var err error
	for service_name, service_config := range env.Config.Service_pool {

		// Preload X509KeyPairs shown by pep to client
		env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_client = loadX509KeyPair(sysLogger, service_config.Cert_shown_by_pep_to_clients_matching_sni, service_config.Privkey_for_cert_shown_by_pep_to_client, "service "+service_name, "external")

		// Preload X509KeyPairs shown by pep to service
		env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_service = loadX509KeyPair(sysLogger, service_config.Cert_shown_by_pep_to_service, service_config.Privkey_for_cert_shown_by_pep_to_service, "service "+service_name, "internal")

		// Preparse Service URL
		env.Config.Service_pool[service_name].Target_service_url, err = url.Parse(service_config.Target_service_addr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target service URL for service %s: %v", service_name, err)
		} else {
			sysLogger.Debugf("target service URL for service %s was successfully parsed", service_name)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, service_config.Cert_pep_accepts_when_shown_by_service, "service "+service_name, env.Config.CA_cert_pool_pep_accepts_from_int)

		// Create a map to directly access service config by SNI
		env.Config.Service_SNI_map = make(map[string]*env.Service_t)
		for _, service := range env.Config.Service_pool {
			env.Config.Service_SNI_map[service.Sni] = service
		}
	}
}

func InitSfPoolParams(sysLogger *logrus.Entry) {
	var err error
	for sf_name, sf_config := range env.Config.Sf_pool {

		// preload X509KeyPairs shown by pep to sf
		env.Config.Sf_pool[sf_name].X509KeyPair_shown_by_pep_to_sf = loadX509KeyPair(sysLogger, sf_config.Cert_shown_by_pep_to_sf, sf_config.Privkey_for_cert_shown_by_pep_to_sf, "service function "+sf_name, "")

		// Preparse SF URL
		env.Config.Sf_pool[sf_name].Target_sf_url, err = url.Parse(sf_config.Target_sf_addr)
		if err != nil {
			sysLogger.Fatalf("Critical Error when parsing target URL for service function %s: %v", sf_name, err)
		} else {
			sysLogger.Debugf("Target URL for service function %s was successfully parsed", sf_name)
		}

		// Preload CA certificate and append it to cert pool
		loadCACertificate(sysLogger, sf_config.Cert_pep_accepts_shown_by_sf, "service function "+sf_name, env.Config.CA_cert_pool_pep_accepts_from_int)
	}
}

func loadX509KeyPair(sysLogger *logrus.Entry, certfile, keyfile, componentName, certAttr string) tls.Certificate {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		sysLogger.Fatalf("Critical Error when loading %s X509KeyPair for %s from %s and %s: %v", certAttr, componentName, certfile, keyfile, err)
	} else {
		sysLogger.Debugf("%s X509KeyPair for %s from %s and %s is successfully loaded", certAttr, componentName, certfile, keyfile)
	}
	return keyPair
}

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

func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logwriter.LW.Logger.WithFields(logrus.Fields{"type": "system"}).Debug("- Ctrl+C pressed in Terminal. Terminating...")
		logwriter.LW.Terminate()
		os.Exit(0)
	}()
}
