// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
)

func UserSessionIsValid(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, cpm *metadata.CpMetadata) bool {
	jwtCookie, err := req.Cookie("ztsfc_session")
	if err != nil {
		return false
	}
	jwtString := jwtCookie.Value

	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Config.BasicAuth.Session.JwtSigningKey), nil
	})

	if err != nil || !token.Valid {
		return false
	}

	username := token.Claims.(jwt.MapClaims)["sub"].(string)

	/*
		failedAttempts, err := getFailedAuthAttempts(sysLogger, username)
		if err != nil {
			sysLogger.Errorf("basic_auth: validUser(): For presented username '%s' the failed PW authentication attempts could not retrieved from PIP: %v.", username, err)
			HandleFormResponse("Internal Error. Try again later", w)
			return false
		}
		if failedAttempts > 3 {
			sysLogger.Errorf("basic_auth: validUser(): Presented username '%s' has too many failed PW authentication attempts", username)
			HandleFormResponse("You user account has been suspended", w)
			return false
		}
	*/

	cpm.User = username
	cpm.PwAuthenticated = true
	cpm.CertAuthenticated = performX509auth(req)

	return true
}

func BasicAuth(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, cpm *metadata.CpMetadata) bool {
	cpm.CertAuthenticated = performX509auth(req)
	if !cpm.CertAuthenticated {
		return false
	}
	cpm.PwAuthenticated = performPasswdAuth(sysLogger, w, req)
	if !cpm.PwAuthenticated {
		return false
	}
	return true
}

func performPasswdAuth(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request) bool {
	var username, password string

	// TODO: Check for JW Token initially
	// Check if it is a POST request
	if req.Method == "POST" {

		if err := req.ParseForm(); err != nil {
			HandleFormResponse("Parsing Error", w)
			return false
		}

		nmbrOfPostvalues := len(req.PostForm)
		if nmbrOfPostvalues != 2 {
			HandleFormResponse("Wrong number of POST form values", w)
			return false
		}

		usernamel, exist := req.PostForm["username"]
		username = usernamel[0]
		if !exist {
			HandleFormResponse("Username not present in POST form", w)
			return false
		}

		if !validUser(sysLogger, username) {
			sysLogger.Errorf("basic_auth: validUser(): presented username '%s' does not exist or is wrong.", username)
			HandleFormResponse("Username or password are not correct", w)
			return false
		}

		failedAttempts, err := getFailedAuthAttempts(sysLogger, username)
		if err != nil {
			sysLogger.Errorf("basic_auth: validUser(): For presented username '%s' the failed PW authentication attempts could not retrieved from PIP: %v.", username, err)
			HandleFormResponse("Internal Error. Try again later", w)
			return false
		}
		if failedAttempts > 3 {
			sysLogger.Errorf("basic_auth: validUser(): Presented username '%s' has too many failed PW authentication attempts", username)
			HandleFormResponse("You user account has been suspended", w)
			return false
		}

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist {
			HandleFormResponse("Password not present in POST form", w)
			sysLogger.Errorf("basic_auth: validPassword(): user '%s' presented no password.", username)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
			return false
		}

		if !validPassword(sysLogger, username, password) {
			HandleFormResponse("Username or password are not correct", w)
			sysLogger.Errorf("basic_auth: validPassword(): presented password for user '%s' is incorrect.", username)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
			return false
		}

		// pushAuthSuccess(sysLogger, username)

		// Create JWT
		jwtToken, err := createJWToken(username)
		if err != nil {
			return false
		}

		ztsfcCookie := http.Cookie{
			Name:   "ztsfc_session",
			Value:  jwtToken,
			MaxAge: 86400,
			Path:   "/",
		}
		http.SetCookie(w, &ztsfcCookie)

		// TODO: make it user configurable
		// TODO: is there a better solution for the content-length  /body length "bug"?
		req.ContentLength = 0
		http.Redirect(w, req, "https://"+req.Host+req.URL.String(), http.StatusSeeOther) // 303
		return false

	} else {
		// HandleFormResponse("only post methods are accepted in this state", w)
		HandleFormResponse("", w)
		return false
	}
}

func createJWToken(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    "ztsfc_pep",
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtString, err := token.SignedString([]byte(config.Config.BasicAuth.Session.JwtSigningKey))
	if err != nil {
		return "", fmt.Errorf("basic_auth: createJWToken(): could not sign token: %v", err)
	}

	return jwtString, nil
}

func performX509auth(req *http.Request) bool {
	// Check if a verified client certificate is present
	if len(req.TLS.VerifiedChains) > 0 {
		return true
	}

	return false
}

func pushAuthFail(sysLogger *logger.Logger, username string) error {
	pushReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.PushUserAttributesUpdateEndpoint, nil)
	if err != nil {
		return fmt.Errorf("attributes: pushAuthFail(): unable to create push user update attribute request for PIP: %w", err)
	}

	pushReqQuery := pushReq.URL.Query()
	pushReqQuery.Set("user", username)
	pushReqQuery.Set("failed-auth-attempt", "1")
	pushReq.URL.RawQuery = pushReqQuery.Encode()

	pipResp, err := config.Config.Pip.PipClient.Do(pushReq)
	if err != nil {
		return fmt.Errorf("attributes: pushAuthFail(): unable to send push user attribute request to PIP: %w", err)
	}

	if pipResp.StatusCode != 200 {
		return nil
	}

	return nil
}

// Not in use anymore
func pushAuthSuccess(sysLogger *logger.Logger, username string) error {
	pushReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.PushUserAttributesUpdateEndpoint, nil)
	if err != nil {
		return fmt.Errorf("attributes: pushAuthSuccess(): unable to create push user update attribute request for PIP: %w", err)
	}

	pushReqQuery := pushReq.URL.Query()
	pushReqQuery.Set("user", username)
	pushReqQuery.Set("success-auth-attempt", "1")
	pushReq.URL.RawQuery = pushReqQuery.Encode()

	pipResp, err := config.Config.Pip.PipClient.Do(pushReq)
	if err != nil {
		return fmt.Errorf("attributes: pushAuthSuccess(): unable to send push user attribute request to PIP: %w", err)
	}

	if pipResp.StatusCode != 200 {
		return nil
	}

	return nil
}

// TODO: Writing an own endpoint for getting failed PW authentications?
func getFailedAuthAttempts(sysLogger *logger.Logger, username string) (int, error) {

	usr := rattr.NewEmptyUser()
	usrReq, err := http.NewRequest("GET", config.Config.Pip.TargetAddr+config.Config.Pip.UserEndpoint, nil)
	if err != nil {
		return -1, fmt.Errorf("attributes: RequestUserAttributes(): unable to create device attribute request for PIP: %w", err)
	}
	usrReqQuery := usrReq.URL.Query()
	usrReqQuery.Set("user", username)
	usrReq.URL.RawQuery = usrReqQuery.Encode()

	pipResp, err := config.Config.Pip.PipClient.Do(usrReq)
	if err != nil {
		return -1, fmt.Errorf("attributes: RequestUserAttributes(): unable to send user request to PIP: %w", err)
	}

	if pipResp.StatusCode != 200 {
		return -1, fmt.Errorf("attributes: RequestUserAttributes(): PIP sent an status code unequal to 200: %w", err)
	}

	err = json.NewDecoder(pipResp.Body).Decode(usr)
	if err != nil {
		return -1, fmt.Errorf("attributes: RequestUserAttributes(): unable to decode the PIP response: %w", err)
	}

	return usr.FailedAuthAttempts, nil
}

func validUser(sysLogger *logger.Logger, username string) bool {
	_, ok := config.Config.BasicAuth.Passwd.PasswdList[username]
	if !ok {
		return false
	}
	return true
}

func validPassword(sysLogger *logger.Logger, username, password string) bool {
	if calcSaltedHash(password, config.Config.BasicAuth.Passwd.PasswdList[username].Salt) == config.Config.BasicAuth.Passwd.PasswdList[username].Digest {
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

func HandleFormResponse(msg string, w http.ResponseWriter) {
	form := `<!DOCTYPE html>
		<html>
		  <head>
			<meta charset="UTF-8">
			<title>Zero Trust Service Function Chaining Login Portal</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<style>
			  body {
				font-family: "Segoe UI", "Roboto", sans-serif;
				background-color: #f2f2f2;
				margin: 0;
			  }
		  
			  .container {
				background-color: #fff;
				border-radius: 5px;
				box-shadow: 0 0 20px rgba(0,0,0,0.2);
				margin: 50px auto;
				padding: 30px;
				max-width: 700px;
			  }
		  
			  h1 {
				font-size: 36px;
				margin: 0 0 20px;
				text-align: center;
				color: #333;
			  }
		  
			  h3 {
				font-size: 18px;
				margin: 0 0 10px;
				text-align: center;
				color: #f44336;
			  }
		  
			  form {
				display: flex;
				flex-direction: column;
				align-items: center;
				margin-top: 20px;
			  }
		  
			  label {
				font-size: 16px;
				color: #333;
				margin-bottom: 5px;
				text-align: left;
				display: block;
				width: 100%;
			  }
		  
			  input[type="text"], input[type="password"] {
				padding: 12px;
				border-radius: 5px;
				border: none;
				background-color: #f2f2f2;
				width: 100%;
				font-size: 16px;
				margin-bottom: 15px;
			  }
		  
			  button[type="submit"] {
				padding: 12px 20px;
				border-radius: 5px;
				border: none;
				background-color: #4caf50;
				color: #fff;
				font-size: 16px;
				cursor: pointer;
				transition: background-color 0.3s ease-in-out;
			  }
		  
			  button[type="submit"]:hover {
				background-color: #3e8e41;
			  }
			</style>
		  </head>
		  <body>
			<div class="container">
			  <h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
			  <h3>` + msg + `</h3>
			  <form method="POST">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required>
				<button type="submit">Log In</button>
			  </form>
			</div>
		  </body>
		</html>	
        `
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, form)
}
