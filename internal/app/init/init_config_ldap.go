// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"strings"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"gopkg.in/ldap.v2"
)

// InitLdapParams() initializes the 'ldap' section of the config file.
// Function currently does nothing.
func initLdap(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.Base == "" {
		fields += "base,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.Host == "" {
		fields += "host,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.Port <= 0 {
		fields += "port,"
	}

	// TODO: Check if the field make sense as well!
	//if config.Config.Ldap.BindDN == "" {
	//	fields += "bind_dn,"
	//}

	// TODO: Check if the field make sense as well!
	//if config.Config.Ldap.BindPassword == "" {
	//	fields += "bind_password,"
	//}

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.UserFilter == "" {
		fields += "user_filter,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.ReadonlyDN == "" {
		fields += "readonly_dn,"
	}

	// TODO: Check if the field make sense as well!
	if config.Config.Ldap.ReadonlyPwPath == "" {
		fields += "readonly_pw_path,"
	}

	// TODO: Check if the field make sense as well!
	//if config.Config.Ldap.GroupFilter == "" {
	//	fields += "group_filter,"
	//}

	// TODO: Check if the field make sense as well!
	if len(config.Config.Ldap.Attributes) == 0 {
		fields += "attributes,"
	}

	if fields != "" {
		return fmt.Errorf("init: InitLdap(): in the section 'ldap' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read password from a file for readonly user
	readonlyPWByteSlice, err := ioutil.ReadFile(config.Config.Ldap.ReadonlyPwPath)
	if err != nil {
		return fmt.Errorf("init: InitLdap(): unable to read a file '%s' with a password for the 'readonly' user: '%s'", config.Config.Ldap.ReadonlyPwPath, err.Error())
	}

	config.Config.Ldap.ReadonlyPW = string(readonlyPWByteSlice)

	// Preload X509KeyPair and write it to config
	config.Config.Ldap.X509KeyPairShownByPepToLdap, err = loadX509KeyPair(sysLogger, config.Config.Ldap.CertShownByPepToLdap, config.Config.Ldap.PrivkeyForCertShownByPepToLdap, "LDAP", "")
	if err != nil {
		return err
	}

	// Preload CA certificate and append it to cert pool
	err = loadCACertificate(sysLogger, config.Config.Ldap.CertPepAcceptsShownByLdap, "LDAP", config.Config.CAcertPoolPepAcceptsFromInt)
	if err != nil {
		return err
	}

	// Create an LDAP connection
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{config.Config.Ldap.X509KeyPairShownByPepToLdap},
		RootCAs:      config.Config.CAcertPoolPepAcceptsFromInt,
		ServerName:   config.Config.Ldap.Host,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		//        InsecureSkipVerify: true,
	}

	config.Config.Ldap.LdapConn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", config.Config.Ldap.Host, config.Config.Ldap.Port), tlsConf)
	if err != nil {
		return fmt.Errorf("init: initLdap(): unable to connect to the LDAP server: %s", err.Error())
	}

	return nil
}
