// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitBasicAuth() ...
func initBasicAuth(sysLogger *logger.Logger) error {
	return initSession(sysLogger)
}

// InitSession() ...
func initSession(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	if config.Config.BasicAuth.Session.Path_to_jwt_pub_key == "" {
		fields += "path_to_jwt_pub_key,"
	}
	sysLogger.Debugf("init: initSession(): JWT Public Key path: '%s'", config.Config.BasicAuth.Session.Path_to_jwt_pub_key)

	if config.Config.BasicAuth.Session.Path_to_jwt_signing_key == "" {
		fields += "path_to_jwt_signing_key,"
	}
	sysLogger.Debugf("init: initSession(): JWT Signing Key path: '%s'", config.Config.BasicAuth.Session.Path_to_jwt_signing_key)

	if fields != "" {
		return fmt.Errorf("init: initSession(): in the section 'session' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	config.Config.BasicAuth.Session.JwtPubKey, err = basic_auth.ParseRsaPublicKeyFromPemFile(config.Config.BasicAuth.Session.Path_to_jwt_pub_key)
	if err != nil {
		return err
	}

	config.Config.BasicAuth.Session.MySigningKey, err = basic_auth.ParseRsaPrivateKeyFromPemFile(config.Config.BasicAuth.Session.Path_to_jwt_signing_key)
	if err != nil {
		return err
	}

	return nil
}
