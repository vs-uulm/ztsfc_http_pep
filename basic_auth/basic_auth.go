package basic_auth

import (
	"net/http"
	//"net/http/httputil"
	//"net/url"
	"fmt"
	//"crypto/tls"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jtblin/go-ldap-client"

	//env "local.com/leobrada/ztsfc_http_pep/env"
	"local.com/leobrada/ztsfc_http_pep/env"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	//    proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

var (
	Jwt_pub_key  *rsa.PublicKey
	MySigningKey *rsa.PrivateKey

//    Jwt_priv_key *rsa.*rsa.PrivateKey
)

func User_sessions_is_valid(req *http.Request, cpm *metadata.Cp_metadata) bool {
	jwt_cookie, err := req.Cookie("ztsfc_session")
	if err != nil {
		return false
	}
	ss := jwt_cookie.Value

	token, err := jwt.Parse(ss, func(token *jwt.Token) (interface{}, error) {
		return Jwt_pub_key, nil
	})

	if err != nil {
		return false
	}

	username := token.Claims.(jwt.MapClaims)["sub"].(string)
	cpm.User = username
	cpm.Pw_authenticated = true
	cpm.Cert_authenticated = perform_x509_auth(req)

	return true
}

func Basic_auth(w http.ResponseWriter, req *http.Request) bool {

	//    proxies.Basic_auth_proxy.ServeHTTP(w, req)
	if perform_passwd_auth(w, req) {
		return true
	}

	return false
}

func perform_passwd_auth(w http.ResponseWriter, req *http.Request) bool {
	var username, password string

	// TODO: Check for JW Token initially
	// Check if it is a POST request
	if req.Method == "POST" {

		if err := req.ParseForm(); err != nil {
			handleFormReponse("Parsing Error", w)
			return false
		}

		nmbr_of_postvalues := len(req.PostForm)
		if nmbr_of_postvalues != 2 {
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

		if !userIsInLDAP(username, password) {
			handleFormReponse("Authentication failed for user", w)
			return false
		}

		// Create JWT
		//MySigningKey := parseRsaiPrivateKeyFromPemStr("./basic_auth/jwt_test_priv.pem")
		ss := createJWToken(MySigningKey, username)
		//fmt.Println(ss)

		ztsfc_cookie := http.Cookie{
			Name:   "ztsfc_session",
			Value:  ss,
			MaxAge: 1800,
			Path:   "/",
		}
		http.SetCookie(w, &ztsfc_cookie)

		// TODO: make it user configurable
		// TODO: is there a better solution for the content-length  /body length "bug"?
		req.ContentLength = 0
		http.Redirect(w, req, "https://"+req.Host+req.URL.String(), 303)
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

	//    fmt.Printf("%v\n", ss)
	return ss
}

func perform_x509_auth(req *http.Request) bool {
	// Check if a verified client certificate is present
	if len(req.TLS.VerifiedChains) > 0 && req.TLS.ServerName == "service1.testbed.informatik.uni-ulm.de" {
		return true
	}

	return false
}

func ParseRsaPublicKeyFromPemStr(pubPEMlocation string) *rsa.PublicKey {
	pub_read_in, err := ioutil.ReadFile(pubPEMlocation)
	if err != nil {
		fmt.Printf("Could not read from file.\n")
		return nil
	}

	block, _ := pem.Decode(pub_read_in)
	if block == nil {
		fmt.Printf("Could not decode the read in block.\n")
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Could not Parse pub key")
		return nil
	}

	return pub.(*rsa.PublicKey)
}

// Just for LCN paper
func Perform_moodle_login(w http.ResponseWriter, req *http.Request) bool {
	_, err := req.Cookie("li")
	if err != nil {
		// Transform existing http request into log POST form
		//        req.Method = "POST"

		// Set cookie presenting that user is logged in
		fmt.Printf("Performing Moodle log in...\n")
		li_cookie := &http.Cookie{
			Name:   "li",
			Value:  "yes",
			MaxAge: 36000,
			Path:   "/",
		}
		//req.AddCookie(li_cookie)
		http.SetCookie(w, li_cookie)
		return true
	}

	fmt.Printf("Cookie is present, user is logged in\n")
	return false

}

func ParseRsaPrivateKeyFromPemStr(privPEMlocation string) *rsa.PrivateKey {
	priv_read_in, err := ioutil.ReadFile(privPEMlocation)
	if err != nil {
		fmt.Printf("Could not read from file.\n")
		return nil
	}

	block, _ := pem.Decode(priv_read_in)
	if block == nil {
		fmt.Printf("Could not decode the read in block.\n")
		return nil
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Print("Could not Parse priv key: \n", err)
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

	//fmt.Println(msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, form)
}

func userIsInLDAP(userName, password string) bool {
	client := &ldap.LDAPClient{
		Base:         env.Config.Ldap.Base,
		Host:         env.Config.Ldap.Host,
		Port:         env.Config.Ldap.Port,
		UseSSL:       env.Config.Ldap.UseSSL,
		BindDN:       env.Config.Ldap.BindDN,
		BindPassword: env.Config.Ldap.BindPassword,
		UserFilter:   env.Config.Ldap.UserFilter,
		GroupFilter:  env.Config.Ldap.GroupFilter,
		Attributes:   env.Config.Ldap.Attributes,
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, _, err := client.Authenticate(userName, password)
	if err != nil {
		fmt.Printf("Error authenticating user %s: %+v\n", userName, err)
		return false
	}
	if !ok {
		fmt.Printf("Authenticating failed for user %s\n", userName)
		return false
	}
	return true
}
