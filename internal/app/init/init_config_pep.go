// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

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
	}

	// Read and parse client CRL
	clientCRLBinary, err := os.ReadFile(config.Config.Pep.ClientCRL)
	if err != nil {
		return fmt.Errorf("initPep(): could not load client CRL: '%s'", err)
	}
	config.Config.CRLForExt, err = x509.ParseRevocationList(clientCRLBinary)
	if err != nil {
		return fmt.Errorf("initPep(): could not parse client CRL: '%s'", err)
	}

	return nil
}
