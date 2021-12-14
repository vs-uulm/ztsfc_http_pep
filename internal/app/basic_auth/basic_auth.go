// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
    "fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/jtblin/go-ldap-client"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
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

func BasicAuth(sysLogger *logwriter.LogWriter, w http.ResponseWriter, req *http.Request) bool {
	return performPasswdAuth(sysLogger, w, req)
}

func performPasswdAuth(sysLogger *logwriter.LogWriter, w http.ResponseWriter, req *http.Request) bool {
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
			handleFormReponse("Username not present or wrong", w)
			return false
		}

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist {
			handleFormReponse("Password not present or wrong", w)
			return false
		}

		if !userIsInLDAP(sysLogger, username, password) {
			handleFormReponse("Authentication failed for user", w)
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

func ParseRsaPublicKeyFromPemStr(sysLogger *logwriter.LogWriter, pubPEMLocation string) *rsa.PublicKey {
	pubReadIn, err := ioutil.ReadFile(pubPEMLocation)
	if err != nil {
		sysLogger.Errorf("JWT Public Key: Could not read from file '%s'", pubPEMLocation)
		return nil
	}

	block, _ := pem.Decode(pubReadIn)
	if block == nil {
        sysLogger.Errorf("JWT Public Key: Could not decode the read in block.\n")
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
        sysLogger.Errorf("JWT Public Key: Could not parse JWT pub key.\n")
		return nil
	}

	return pub.(*rsa.PublicKey)
}

// Just for LCN paper; function currently not in use
//func PerformMoodleLogin(w http.ResponseWriter, req *http.Request) bool {
//	_, err := req.Cookie("li")
//	if err != nil {
//		// Transform existing http request into log POST form
//		//        req.Method = "POST"
//
//		// Set cookie presenting that user is logged in
//		fmt.Printf("Performing Moodle log in...\n")
//		liCookie := &http.Cookie{
//			Name:   "li",
//			Value:  "yes",
//			MaxAge: 36000,
//			Path:   "/",
//		}
//		//req.AddCookie(liCookie)
//		http.SetCookie(w, liCookie)
//		return true
//	}
//
//	fmt.Printf("Cookie is present, user is logged in\n")
//	return false
//
//}

func ParseRsaPrivateKeyFromPemStr(sysLogger *logwriter.LogWriter, privPEMLocation string) *rsa.PrivateKey {
	privReadIn, err := ioutil.ReadFile(privPEMLocation)
	if err != nil {
		sysLogger.Errorf("JWT Signing Key: Could not read from file '%s'", privPEMLocation)
		return nil
	}

	block, _ := pem.Decode(privReadIn)
	if block == nil {
		sysLogger.Errorf("JWT Signing Key: Could not decode the read in block.\n")
		return nil
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		sysLogger.Errorf("JWT Signing Key: Could not parse signing key.\n")
		return nil
	}

	return priv.(*rsa.PrivateKey)
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

func userIsInLDAP(sysLogger *logwriter.LogWriter, userName, password string) bool {
	// retrieve connection parameters from config file instead of hard coding

	client := &ldap.LDAPClient{
		Base:         config.Config.Ldap.Base,
		Host:         config.Config.Ldap.Host,
		Port:         config.Config.Ldap.Port,
		UseSSL:       config.Config.Ldap.UseSSL,
		BindDN:       config.Config.Ldap.BindDN,
		BindPassword: config.Config.Ldap.BindPassword,
		UserFilter:   config.Config.Ldap.UserFilter,
		GroupFilter:  config.Config.Ldap.GroupFilter,
		Attributes:   config.Config.Ldap.Attributes,
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, _, err := client.Authenticate(userName, password)
	if err != nil {
        sysLogger.Errorf("Error authenticating user %s: %+v\n", userName, err)
		return false
	}
	if !ok {
        sysLogger.Errorf("Authenticating failed for user %s\n", userName)
		return false
	}
	return true
}
