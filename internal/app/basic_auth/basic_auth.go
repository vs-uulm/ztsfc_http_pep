// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
    "crypto/sha512"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
)

func UserSessionIsValid(req *http.Request, cpm *metadata.CpMetadata) bool {
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
			handleFormReponse("Parsing Error", w)
			return false
		}

		nmbrOfPostvalues := len(req.PostForm)
		if nmbrOfPostvalues != 2 {
			handleFormReponse("Wrong number of POST form values", w)
			return false
		}

		usernamel, exist := req.PostForm["username"]
		username = usernamel[0]
		if !exist {
			handleFormReponse("Username not present.", w)
			return false
		}

        if !validUser(sysLogger, username) {
            sysLogger.Errorf("basic_auth: validUser(): presented username '%s' does not exist or is wrong.", username)
            return false
        }

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist {
			handleFormReponse("Password not present.", w)
            if err := pushPWAuthenticationFail(sysLogger, username); err != nil {
                sysLogger.Errorf("%v", err)
            }
			return false
		}

        if !validPassword(sysLogger, username, password) {
            sysLogger.Errorf("basic_auth: validPassword(): presented password for user '%s' is incorrect.", username)
            return false
        }

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
		handleFormReponse("only post methods are accepted in this state", w)
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

func handleFormReponse(msg string, w http.ResponseWriter) {
	form := `<html>
        <body>
        <center>
        <form action="/" method="post">
        <label for="fname">Username:</label>
        <input type="text" id="username" name="username"><br><br>
        <label for="lname">Password:</label>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Submit">
        </form>
        </center>
        </body>
        </html>
        `
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, form)
}

func pushPWAuthenticationFail(sysLogger *logger.Logger, username string) error {
    pushReq, err := http.NewRequest("POST", config.Config.Pip.TargetAddr+config.Config.Pip.PushUserAttributesUpdateEndpoint, nil)
    if err != nil {
        return fmt.Errorf("attributes: pushPWAuthenticationFail(): unable to create push user update attribute request for PIP: %w", err)
    }

    pushReqQuery := pushReq.URL.Query()
    pushReqQuery.Set("user", username)
    pushReqQuery.Set("failed-pw-authentication", "1")
    pushReq.URL.RawQuery = pushReqQuery.Encode()

    pipResp, err := config.Config.Pip.PipClient.Do(pushReq)
    if err != nil {
        return fmt.Errorf("attributes: pushPWAuthenticationFail(): unable to send push user attribute request to PIP: %w", err)
    }

    if pipResp.StatusCode != 200 {
        return nil
    }

    return nil
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
