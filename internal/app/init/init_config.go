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
	"os"
	"os/signal"
	"syscall"

	logger "github.com/vs-uulm/ztsfc_http_logger"
)

func InitConfig(sysLogger *logger.Logger) error {
	initDefaultValues(sysLogger)

	if err := initBlocklists(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initPep(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initBasicAuth(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initLdap(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initPdp(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initSfpl(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initServicePool(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
	}

	if err := initSfPool(sysLogger); err != nil {
		return fmt.Errorf("init: InitConfig(): %v", err)
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

	// Return error if provided certificate is nil
	if certPool == nil {
		return errors.New("provided certPool is nil")
	}

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
