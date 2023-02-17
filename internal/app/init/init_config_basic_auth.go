// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"
	"errors"
	"os"
	"bufio"

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

	if err = initSession(sysLogger); err != nil {
		return fmt.Errorf("initBasicAuth(): %v", err)
	}

	return nil
}

func initPasswd(sysLogger *logger.Logger) error {
	var err error
	config.Config.BasicAuth.Passwd.PasswdList = make(map[string]config.ShadowT)

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
		if strings.Count(line, ":") != 2 {
            sysLogger.Infof("init: InitConfig(): initBasicAuth(): initPasswd(): line number %d has incorrect syntax", lineCount)
            continue
        }
        values := strings.Split(line, ":")
		
		if len(values[0]) > 100 || len(values[1]) > 100 || len(values[2]) > 128 {
			fmt.Printf("%s\n", values[2])
			sysLogger.Infof("init: InitConfig(): initBasicAuth(): initPasswd(): not processing invalid line at line number %d...", lineCount)
			continue
		}

		config.Config.BasicAuth.Passwd.PasswdList[values[0]] = config.ShadowT{Salt: values[1], Digest: values[2]}
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
