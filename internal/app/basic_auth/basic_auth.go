// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
    "crypto/sha512"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
)

func UserSessionIsValid(req *http.Request, cpm *metadata.CpMetadata) bool {
	jwtCookie, err := req.Cookie("ztsfc_session")
	if err != nil {
		return false
	}
	ss := jwtCookie.Value

	token, err := jwt.Parse(ss, func(token *jwt.Token) (interface{}, error) {
		return config.Config.BasicAuth.Session.JwtPubKey, nil
	})

	if err != nil {
		return false
	}

	username := token.Claims.(jwt.MapClaims)["sub"].(string)
	cpm.User = username
	cpm.PwAuthenticated = true
	cpm.CertAuthenticated = performX509auth(req)

	return true
}

func BasicAuth(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request) bool {
	return performPasswdAuth(sysLogger, w, req)
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
		//config.Config.BasicAuth.Session.MySigningKey := parseRsaiPrivateKeyFromPemStr("./basic_auth/jwt_test_priv.pem")
		ss := createJWToken(config.Config.BasicAuth.Session.MySigningKey, username)

		ztsfcCookie := http.Cookie{
			Name:   "ztsfc_session",
			Value:  ss,
			MaxAge: 1800,
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

func createJWToken(mySigningKey *rsa.PrivateKey, username string) string {
	// ! ToDo: deprecated! REplace by jwt.RegisteredClaims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		Issuer:    "ztsfc_bauth",
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, _ := token.SignedString(mySigningKey)

	return ss
}

func performX509auth(req *http.Request) bool {
	// Check if a verified client certificate is present
	if len(req.TLS.VerifiedChains) > 0 && req.TLS.ServerName == "service1.testbed.informatik.uni-ulm.de" {
		return true
	}

	return false
}

// ParseRsaPublicKeyFromPemFile() loads rsa.PublicKey from a PEM file
func ParseRsaPublicKeyFromPemFile(pubPEMLocation string) (*rsa.PublicKey, error) {
	// Read a file content and convert it to a PEM block
	pemBlock, err := readFirstPEMBlockFromFile(pubPEMLocation)
	if err != nil {
		return nil, fmt.Errorf("basic_auth: ParseRsaPublicKeyFromPemFile(): %w", err)
	}

	if !strings.Contains(pemBlock.Type, "PUBLIC KEY") {
		fmt.Printf("pemBlock.Type = %#v\n", pemBlock.Type)
		return nil, errors.New("basic_auth: ParseRsaPublicKeyFromPemFile(): provided file does not contain a PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err == nil {
		return pub.(*rsa.PublicKey), nil
	}

	pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err == nil {
		return pub.(*rsa.PublicKey), nil
	}

	// Another Public keys form parsing functions can be added here later
	// ...

	return nil, fmt.Errorf("basic_auth: ParseRsaPublicKeyFromPemFile(): unable to parse JWT public key: %w", err)
}

// ParseRsaPrivateKeyFromPemFile() loads rsa.PrivateKey from a PEM file
func ParseRsaPrivateKeyFromPemFile(privPEMLocation string) (*rsa.PrivateKey, error) {
	// Read a file content and convert it to a PEM block
	pemBlock, err := readFirstPEMBlockFromFile(privPEMLocation)
	if err != nil {
		return nil, fmt.Errorf("basic_auth: ParseRsaPrivateKeyFromPemFile(): %w", err)
	}

	if !strings.Contains(pemBlock.Type, "PRIVATE KEY") {
		return nil, errors.New("basic_auth: ParseRsaPrivateKeyFromPemFile(): provided file does not contain a PEM private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err == nil {
		return priv.(*rsa.PrivateKey), nil
	}

	priv, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err == nil {
		return priv.(*rsa.PrivateKey), nil
	}

	// Another Private keys form parsing functions can be added here later
	// ...

	return nil, fmt.Errorf("basic_auth: ParseRsaPrivateKeyFromPemFile(): unable to parse JWT private key: %w", err)
}

// ReadFirstPEMBlockFromFile() loads the first PEM block of a given PEM key file into a pem.Block structure
func readFirstPEMBlockFromFile(path string) (*pem.Block, error) {
	// Read the file content
	pubReadIn, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode the file content as a PEM block
	block, _ := pem.Decode(pubReadIn)
	if block == nil {
		return nil, fmt.Errorf("unable to decode a byte slice as a PEM block: %w", err)
	}

	return block, nil
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
