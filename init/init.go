package init

import (
	env "local.com/leobrada/ztsfc_http_pep/env"
	logwriter "local.com/leobrada/ztsfc_http_pep/logwriter"
	"crypto/tls"
	"net/url"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
)

func LoadServicePool(config env.Config_t, lw *logwriter.LogWriter) error {
	var err error
	for service_name, service_config := range(env.Config.Service_pool) {
	
		// Preload X509KeyPairs shown by pep to client
		env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_client, err = 
			tls.LoadX509KeyPair(
				service_config.Cert_shown_by_pep_to_clients_matching_sni,
				service_config.Privkey_for_cert_shown_by_pep_to_client)
		if err != nil {
			lw.Logger.Fatalf("Critical Error when loading external X509KeyPair for service %s from %s and %s: %v", service_name, service_config.Cert_shown_by_pep_to_clients_matching_sni, service_config.Privkey_for_cert_shown_by_pep_to_client, err)
		} else {
			lw.Logger.Debugf("External X509KeyPair for service %s from %s and %s is successfully loaded\n",service_name, service_config.Cert_shown_by_pep_to_clients_matching_sni, 				service_config.Privkey_for_cert_shown_by_pep_to_client)
		}

		// Preload X509KeyPairs shown by pep to service
		env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_service, err =
			tls.LoadX509KeyPair(
				service_config.Cert_shown_by_pep_to_service,
				service_config.Privkey_for_cert_shown_by_pep_to_service)
		if err != nil {
			lw.Logger.Fatalf("Critical Error when loading internal X509KeyPair for service %s from %s and %s: %v", service_name, service_config.Cert_shown_by_pep_to_service, service_config.Privkey_for_cert_shown_by_pep_to_service, err)
		} else {
			lw.Logger.Debugf("Internal X509KeyPair for service %s from %s and %s is successfully loaded\n", service_name, service_config.Cert_shown_by_pep_to_clients_matching_sni,	service_config.Privkey_for_cert_shown_by_pep_to_client)
		}

		// Preparse Service URL
		env.Config.Service_pool[service_name].Target_service_url, err = url.Parse(service_config.Target_service_addr)
		if err != nil {
			lw.Logger.Fatalf("Critical Error when parsing target service URL for service %s: %v", service_name, err)
		} else {
			lw.Logger.Debugf("target service URL for service %s was successfully parsed\n", service_name)
		}
	}
	return err
}

func LoadSfPool(config env.Config_t, lw *logwriter.LogWriter) error {
	var err error
	for sf_name, sf_config := range(env.Config.Sf_pool) {
		// preload X509KeyPairs shown by pep to sf
		env.Config.Sf_pool[sf_name].X509KeyPair_shown_by_pep_to_sf, err = tls.LoadX509KeyPair(
			sf_config.Cert_shown_by_pep_to_sf,
			sf_config.Privkey_for_cert_shown_by_pep_to_sf)
		if err != nil {
			lw.Logger.Fatalf("Critical Error when loading X509KeyPair for service function %s from %s and %s: %v", sf_name, sf_config.Cert_shown_by_pep_to_sf, sf_config.Privkey_for_cert_shown_by_pep_to_sf, err)
		} else {
			lw.Logger.Debugf("X509KeyPair for service function %s from %s and %s is successfully loaded\n",sf_name, sf_config.Cert_shown_by_pep_to_sf, sf_config.Privkey_for_cert_shown_by_pep_to_sf)
		}

		// Preparse SF URL
		env.Config.Sf_pool[sf_name].Target_sf_url, err = url.Parse(sf_config.Target_sf_addr)
		if err != nil {
			lw.Logger.Fatalf("Critical Error when parsing target URL for service function %s: %v", sf_name, err)
		} else {
			lw.Logger.Debugf("Target URL for service function %s was successfully parsed\n", sf_name)
		}
	}
	return err
}

func InitAllCACertificates(lw *logwriter.LogWriter) error {
	var caRoot []byte
	var err error

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range env.Config.Pep.Certs_pep_accepts_when_shown_by_clients {
		caRoot, err = ioutil.ReadFile(acceptedClientCert)
		if err != nil {
			lw.Logger.Fatalf("Loading client CA certificate from %s error\n", acceptedClientCert)
		} else {
			lw.Logger.Debugf("Client CA certificate from %s is successfully loaded\n", acceptedClientCert)
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_ext.AppendCertsFromPEM(caRoot)
	}

	// Read CA certs used for signing client certs and are accepted by the PEP
	for service_name, service_config := range env.Config.Service_pool {
		caRoot, err = ioutil.ReadFile(service_config.Cert_pep_accepts_when_shown_by_service)
		if err != nil {
			lw.Logger.Fatalf("Loading service %s CA certificate from %s error\n", service_name, service_config.Cert_pep_accepts_when_shown_by_service)
		} else {
			lw.Logger.Debugf("Service %s CA certificate from %s is successfully loaded\n", service_name, service_config.Cert_pep_accepts_when_shown_by_service)
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_int.AppendCertsFromPEM(caRoot)
	}

	for sf_name, sf_config := range env.Config.Sf_pool {
		caRoot, err = ioutil.ReadFile(sf_config.Cert_pep_accepts_shown_by_sf)
		if err != nil {
			lw.Logger.Fatalf("Loading service function %s CA certificate from %s error\n", sf_name, sf_config.Cert_pep_accepts_shown_by_sf)
		} else {
			lw.Logger.Debugf("Service function %s CA certificate from %s is successfully loaded\n", sf_name, sf_config.Cert_pep_accepts_shown_by_sf)
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_int.AppendCertsFromPEM(caRoot)
	}
	return err
}

func SetupCloseHandler(lw *logwriter.LogWriter) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		lw.Logger.Debug("- Ctrl+C pressed in Terminal. Terminating...")
		lw.Terminate()
		os.Exit(0)
	}()
}
