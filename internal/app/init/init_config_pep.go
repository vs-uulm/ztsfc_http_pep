// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	gct "github.com/leobrada/golang_convenience_tools"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitPepParams() initializes the 'pep' section of the config file and
// loads the PEP certificate(s).
func initPep(sysLogger *logger.Logger) error {
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
		return fmt.Errorf("initPep(): in the section 'pep' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used for signing client certs and are accepted by the PEP
	for _, acceptedClientCert := range config.Config.Pep.CertsPepAcceptsWhenShownByClients {
		err = gct.LoadCACertificate(acceptedClientCert, config.Config.CAcertPoolPepAcceptsFromExt)
		if err != nil {
			return fmt.Errorf("initPep(): could not load certificates PEP accepts from clients: '%s'", err)
		}
		config.Config.CACertSlicePEPAcceptsFromExt, err = AppendPEMCertificateToCertSlice(sysLogger, acceptedClientCert,
			config.Config.CACertSlicePEPAcceptsFromExt)
		if err != nil {
			return fmt.Errorf("initPep(): could not add certificates PEP accepts from clients: '%s'", err)
		}
	}

	// Read, parse, and verify client CRL
	clientCRLBinary, err := os.ReadFile(config.Config.Pep.ClientCRL)
	if err != nil {
		return fmt.Errorf("initPep(): could not load client CRL: '%s'", err)
	}
	config.Config.CRLForExt, err = x509.ParseRevocationList(clientCRLBinary)
	if err != nil {
		return fmt.Errorf("initPep(): could not parse client CRL: '%s'", err)
	}

	if (config.Config.CRLForExt.ThisUpdate.Compare(time.Now()) != -1) || (config.Config.CRLForExt.NextUpdate.Compare(time.Now()) != 1) {
		return fmt.Errorf("initPep(): client CRL lies outside of valid time period")
	}

	sysLogger.Debugf("Length of config.Config.CACertSlicePEPAcceptsFromExt: %d", len(config.Config.CACertSlicePEPAcceptsFromExt))
	for _, caCert := range config.Config.CACertSlicePEPAcceptsFromExt {
		if err = config.Config.CRLForExt.CheckSignatureFrom(caCert); err == nil {
			sysLogger.Infof("Signature for CRL '%s' could be successfully verified by CA cert '%s'", config.Config.Pep.ClientCRL, caCert.Subject.CommonName)
			break
		}
	}
	if err != nil {
		return fmt.Errorf("initPep(): could not verify CRL signature: '%s'", err)
	}

	return nil
}

func AppendPEMCertificateToCertSlice(sysLogger *logger.Logger, certfile string, certSlice []*x509.Certificate) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certfile)
	if err != nil {
		return certSlice, fmt.Errorf("AppendPEMCertificateToCertSlice(): Loading CA certificate from %s error: %v", certfile, err)
	}

	if certSlice != nil {
		certDER, _ := pem.Decode(certPEM)
		if certDER == nil {
			sysLogger.Debugf("No PEM data could be found")
			return certSlice, fmt.Errorf("AppendPEMCertificateToCertSlice(): In passed cert slice '%s' no PEM data is found", certfile)
		}

		if certDER.Type != "CERTIFICATE" {
			sysLogger.Debugf("Cert is not a CERTIFICATE")
			return certSlice, fmt.Errorf("AppendPEMCertificateToCertSlice(): In passed cert slice '%s' no CERTIFICATE is found", certfile)
		}

		cert, err := x509.ParseCertificate(certDER.Bytes)
		if err != nil {
			sysLogger.Debugf("Cert could not bet parsed")
			return certSlice, fmt.Errorf("AppendPEMCertificateToCertSlice(): Decoded PEM CERTIFICATE could not be parsed to X509: %v", err)
		}

		certSlice = append(certSlice, cert)
		return certSlice, nil
	}

	return certSlice, fmt.Errorf("AppendPEMCertificateToCertSlice(): Passed cert slice is nil")
}
