// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	gct "github.com/leobrada/golang_convenience_tools"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/basic_auth"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

// InitBasicAuth() ...
func initBasicAuth(sysLogger *logger.Logger) error {
	var err error
	if err = initPasswd(sysLogger); err != nil {
		return fmt.Errorf("initBasicAuth(): %v", err)
	}

	if err = initWebAuthnContext(sysLogger); err != nil {
		return fmt.Errorf("initBasicAuth(): %v", err)
	}

	if err = initSession(sysLogger); err != nil {
		return fmt.Errorf("initBasicAuth(): %v", err)
	}

	return nil
}

func initPasswd(sysLogger *logger.Logger) error {
	var err error
	config.Config.BasicAuth.Passwd.PasswdListByUsername = make(map[string]*config.ShadowT)
	config.Config.BasicAuth.Passwd.PasswdListByID = make(map[string]*config.ShadowT)

	if config.Config.BasicAuth.Passwd.PathToPasswd == "" {
		return errors.New("initPasswd(): path to passwd file is not defined")
	}

	passwdFileInfo, err := os.Stat(config.Config.BasicAuth.Passwd.PathToPasswd)
	if err != nil {
		return fmt.Errorf("initPasswd(): could not check file '%s' at given path to passwd: %v", config.Config.BasicAuth.Passwd.PathToPasswd, err)
	}
	if passwdFileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("initPasswd(): symbolic links are forbidden for the passwd file")
	}

	passwdFile, err := os.Open(config.Config.BasicAuth.Passwd.PathToPasswd)
	if err != nil {
		return fmt.Errorf("initPasswd(): could not open file '%s' at given path to passwd", config.Config.BasicAuth.Passwd.PathToPasswd)
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)
	scanner.Buffer(nil, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 100 {
			sysLogger.Infof("init: InitConfig(): initBasicAuth(): initPasswd(): Stopped after reading in 100 Lines from passwd file...")
			break
		}
		line := scanner.Text()
		if strings.Count(line, ":") != 3 {
			sysLogger.Infof("init: InitConfig(): initBasicAuth(): initPasswd(): line number %d has incorrect syntax", lineCount)
			continue
		}
		values := strings.Split(line, ":")

		if len(values[0]) > 100 || len(values[1]) > 64 || len(values[2]) > 100 || len(values[3]) > 128 {
			fmt.Printf("%s\n", values[2])
			sysLogger.Infof("init: InitConfig(): initBasicAuth(): initPasswd(): not processing invalid line at line number %d...", lineCount)
			continue
		}

		config.Config.BasicAuth.Passwd.PasswdListByUsername[values[0]] = &config.ShadowT{User: values[0], ID: []byte(values[1]), Salt: values[2], Digest: values[3]}
		config.Config.BasicAuth.Passwd.PasswdListByID[values[1]] = &config.ShadowT{User: values[0], ID: []byte(values[1]), Salt: values[2], Digest: values[3]}
	}

	if err = scanner.Err(); err != nil {
		return fmt.Errorf("initPasswd(): errors occurred during reading file '%s': %v", config.Config.BasicAuth.Passwd.PathToPasswd, err)
	}

	// go reloadPasswd(sysLogger)

	return nil
}

// InitSession() ...
func initSession(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	if config.Config.BasicAuth.Session.PathToJwtSigningKey == "" {
		fields += "path_to_jwt_signing_key,"
	}
	sysLogger.Debugf("init: initSession(): JWT Signing Key path: '%s'", config.Config.BasicAuth.Session.PathToJwtSigningKey)

	if fields != "" {
		return fmt.Errorf("init: initSession(): in the section 'session' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	config.Config.BasicAuth.Session.JwtSigningKey, err = gct.ReadBytesFromFileAsString(config.Config.BasicAuth.Session.PathToJwtSigningKey, 64)
	if err != nil {
		return fmt.Errorf("init: initSession(): Could not read in JWT signing key: %v", err)
	}

	return nil
}

func initWebAuthnContext(sysLogger *logger.Logger) error {
	// Collect RPOrigins
	rporigins := []string{}
	for _, value := range config.Config.ServicePool {
		rporigins = append(rporigins, "https://"+value.Sni)
	}

	// Create a new WebAuthn config
	webAuthnConfig := &webauthn.Config{
		RPDisplayName: "ZTSFC WebAuthn",
		RPID:          config.Config.BasicAuth.RPID,
		RPOrigins:     rporigins,
	}

	// Create a new WebAuthn object
	var err error
	basic_auth.WebAuthnContext, err = webauthn.New(webAuthnConfig)
	return err
}
