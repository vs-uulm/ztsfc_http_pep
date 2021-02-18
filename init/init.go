package init

import (
    env "local.com/leobrada/ztsfc_http_pep/env"
    logr "local.com/leobrada/ztsfc_http_pep/logwriter"
    "crypto/tls"
    "log"
    "net/url"
    "fmt"
    "io/ioutil"
)

func LoadServicePool(config env.Config_t) error {
    var err error
    for service_name, service_config := range(env.Config.Service_pool) {
        // Preload X509KeyPairs shown by pep to client
        env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_client, err = tls.LoadX509KeyPair(
            service_config.Cert_shown_by_pep_to_clients_matching_sni,
            service_config.Privkey_for_cert_shown_by_pep_to_client)
        if err != nil {
            log.Print("Loading X509KeyPair Critical Error", err)
            return err
        }
        // Preload X509KeyPairs shown by pep to service
        env.Config.Service_pool[service_name].X509KeyPair_shown_by_pep_to_service, err = tls.LoadX509KeyPair(
            service_config.Cert_shown_by_pep_to_service,
            service_config.Privkey_for_cert_shown_by_pep_to_service)
        if err != nil {
            log.Print("Loading X509KeyPair Critical Error", err)
            return err
        }
        // Preparse Service URL
        env.Config.Service_pool[service_name].Target_service_url, err = url.Parse(service_config.Target_service_addr)
        if err != nil {
            log.Print("Parsing Target Service URL Critical Error", err)
            return err
        }
    }
    return err
}

func LoadSfPool(config env.Config_t) error {
    var err error
    for sf_name, sf_config := range(env.Config.Sf_pool) {
        // preload X509KeyPairs shown by pep to sf
        env.Config.Sf_pool[sf_name].X509KeyPair_shown_by_pep_to_sf, err = tls.LoadX509KeyPair(
            sf_config.Cert_shown_by_pep_to_sf,
            sf_config.Privkey_for_cert_shown_by_pep_to_sf)
        if err != nil {
            log.Print("Loading X509KeyPair Critical Error", err)
            return err
        }
        // Preparse SF URL
        env.Config.Sf_pool[sf_name].Target_sf_url, err = url.Parse(sf_config.Target_sf_addr)
        if err != nil {
            log.Print("Parsing Target SF URL Critical Error", err)
            return err
        }
    }
    return err
}

func InitAllCACertificates() error {
	var caRoot []byte
	var err error
	isErrorDetected := false

	// Read CA certs used for signing client certs and are accepted by the PEP
	logr.Log_writer.Log("Loading clients CA certificates:\n")
	for _, acceptedClientCert := range env.Config.Pep.Certs_pep_accepts_when_shown_by_clients {
		caRoot, err = ioutil.ReadFile(acceptedClientCert)
		if err != nil {
			isErrorDetected = true
			logr.Log_writer.Log(fmt.Sprintf("    - %s - FAILED\n", acceptedClientCert))
		} else {
			logr.Log_writer.Log(fmt.Sprintf("    - %s - OK\n", acceptedClientCert))
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_ext.AppendCertsFromPEM(caRoot)
	}

	// Read CA certs used for signing client certs and are accepted by the PEP
	if len(env.Config.Service_pool) > 0 {
		logr.Log_writer.Log("Loading CA certificates for services:\n")
	}
	for service_name, service_config := range env.Config.Service_pool {
		caRoot, err = ioutil.ReadFile(service_config.Cert_pep_accepts_when_shown_by_service)
		if err != nil {
			isErrorDetected = true
			logr.Log_writer.Log(fmt.Sprintf("    %s: %s - FAILED\n", service_name,
				service_config.Cert_pep_accepts_when_shown_by_service))
		} else {
			logr.Log_writer.Log(fmt.Sprintf("    %s: %s - OK\n", service_name,
				service_config.Cert_pep_accepts_when_shown_by_service))
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_int.AppendCertsFromPEM(caRoot)
	}

	if len(env.Config.Sf_pool) > 0 {
		logr.Log_writer.Log("Loading CA certificates for service functions:\n")
	}
	for sf_name, sf_config := range env.Config.Sf_pool {
		caRoot, err = ioutil.ReadFile(sf_config.Cert_pep_accepts_shown_by_sf)
		if err != nil {
			isErrorDetected = true
			logr.Log_writer.Log(fmt.Sprintf("    %s: %s - FAILED\n", sf_name,
				sf_config.Cert_pep_accepts_shown_by_sf))
		} else {
			logr.Log_writer.Log(fmt.Sprintf("    %s: %s - OK\n", sf_name,
				sf_config.Cert_pep_accepts_shown_by_sf))
		}
		// Append a certificate to the pool
		env.Config.CA_cert_pool_pep_accepts_from_int.AppendCertsFromPEM(caRoot)
	}

	if isErrorDetected {
		log.Print("An error occurred during certificates loading. See details in the log file.")
	}
    return err
}
