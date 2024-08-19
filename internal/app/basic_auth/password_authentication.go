// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
	"crypto/sha512"
	"fmt"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/resources"
)

func performPasswdAuth(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request) {
	var password string

	if req.Method == "POST" {

		if feedback, err := handleForm(sysLogger, req); err != nil {
			sysLogger.Errorf("basic_auth: performPasswdAuth(): %v", err)
			HandlePwdAuth(feedback, w)
			return
		}

		username, feedback, err := handleUsername(sysLogger, req)
		if err != nil {
			sysLogger.Errorf("basic_auth: performPasswdAuth(): %v", err)
			HandlePwdAuth(feedback, w)
			return
		}

		if feedback, err = handleFailedAuthAttempts(sysLogger, req, username); err != nil {
			sysLogger.Errorf("basic_auth: performPasswdAuth(): %v", err)
			HandlePwdAuth(feedback, w)
			return
		}

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist {
			sysLogger.Errorf("basic_auth: performPasswdAuth(): In HTTP POST request from %s, user '%s' presented no password", req.Host, username)
			HandlePwdAuth("Password not present in POST form", w)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
			return
		}

		if !validPassword(sysLogger, username, password) {
			HandlePwdAuth("Invalid username or password", w)
			sysLogger.Errorf("basic_auth: validPassword(): In HTTP POST request from %s, presented password for user '%s' is incorrect", req.Host, username)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
			return
		}

		// pushAuthSuccess(sysLogger, username)
		if err = setCookieAndFinishAuthentication(sysLogger, w, req, username, "password"); err != nil {
			HandlePwdAuth("Internal Error. Try again later", w)
			sysLogger.Errorf("basic_auth: validPassword(): In HTTP POST request from %s, for user '%s' no session cookie could be created", req.Host, username)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
		}
		return

	} else {
		// HandlePwdAuth("only post methods are accepted in this state", w)
		HandlePwdAuth("", w)
		return
	}
}

func validUser(sysLogger *logger.Logger, username string) bool {
	_, ok := config.Config.BasicAuth.Passwd.PasswdListByUsername[username]
	return ok
}

func validPassword(sysLogger *logger.Logger, username, password string) bool {
	// Check if user has password authentication enabled
	if config.Config.BasicAuth.Passwd.PasswdListByUsername[username].Digest == "" {
		return false
	}
	if calcSaltedHash(password, config.Config.BasicAuth.Passwd.PasswdListByUsername[username].Salt) == config.Config.BasicAuth.Passwd.PasswdListByUsername[username].Digest {
		return true
	} else {
		return false
	}
}

func calcSaltedHash(password, salt string) string {
	passwordWithSalt := password + salt
	digest := sha512.Sum512([]byte(passwordWithSalt))
	return fmt.Sprintf("%x", digest)
}

// TODO: make it private; call in router.go prevents it currently
func HandlePwdAuth(msg string, w http.ResponseWriter) {
	pwdAuthPage := resources.GeneratePwdAuthPage(msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, pwdAuthPage)
}

func handleForm(sysLogger *logger.Logger, req *http.Request) (string, error) {
	if err := req.ParseForm(); err != nil {
		return "Parsing Error", fmt.Errorf("handleForm(): HTTP POST request from %s could not be parsed", req.Host)
	}

	nmbrOfPostvalues := len(req.PostForm)
	if nmbrOfPostvalues != 2 {
		return "Wrong number of POST form values", fmt.Errorf("handleForm(): HTTP POST request from %s has wrong number of POST form values", req.Host)
	}

	return "", nil
}

func handleUsername(sysLogger *logger.Logger, req *http.Request) (string, string, error) {
	usernamel, exist := req.PostForm["username"]
	if len(usernamel) < 1 {
		return "", "Internal Error. Try again later", fmt.Errorf("handleUsername(): No user exist in user DB")
	}

	username := usernamel[0]
	if !exist {
		return "", "Username not present in POST form", fmt.Errorf("handleUsername(): HTTP POST request from %s did not provide a username", req.Host)
	}

	if !validUser(sysLogger, username) {
		return "", "Invalid username or password", fmt.Errorf("handleUsername(): In HTTP POST request from %s, presented username '%s' does not exist or is wrong", req.Host, username)
	}

	return username, "", nil
}

func handleFailedAuthAttempts(sysLogger *logger.Logger, req *http.Request, username string) (string, error) {
	failedAttempts, err := getFailedAuthAttempts(sysLogger, username)
	if err != nil {
		return "Internal Error. Try again later", fmt.Errorf("handleFailedAuthAttempts(): In HTTP POST request from %s, for presented username '%s' the failed PW authentication attempts could not retrieved from PIP: %v", req.Host, username, err)
	}
	// TODO: Implement time delay; not a DoS
	if failedAttempts > 5 {
		return "You user account has been suspended", fmt.Errorf("handleFailedAuthAttempts(): In HTTP POST request from %s, presented username '%s' has too many failed PW authentication attempts", req.Host, username)
	}

	return "", nil
}
