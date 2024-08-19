// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	rattr "github.com/vs-uulm/ztsfc_http_attributes"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/resources"
)

type ZTSFCClaims struct {
	UserAuthType string `json:"at"`
	jwt.RegisteredClaims
}

func ClientHasValidSession(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, cpm *metadata.CpMetadata) bool {
	jwtCookie, err := req.Cookie("ztsfc_session")
	if err != nil {
		return false
	}
	jwtString := jwtCookie.Value

	token, err := jwt.ParseWithClaims(jwtString, &ZTSFCClaims{}, func(token *jwt.Token) (interface{}, error) {
		//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		//	return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		//}
		return []byte(config.Config.BasicAuth.Session.JwtSigningKey), nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		sysLogger.Errorf("basic_auth: ClientHasValidSession(): %v", err)
		return false
	}

	if !token.Valid {
		sysLogger.Errorf("basic_auth: ClientHasValidSession(): client provided invalid jwt token")
		return false
	}

	claims, ok := token.Claims.(*ZTSFCClaims)
	if !ok {
		sysLogger.Errorf("basic_auth: ClientHasValidSession(): could not parse jwt claims")
	}

	cpm.User = claims.Subject
	if claims.UserAuthType == "password" {
		cpm.PwAuthenticated = true
		cpm.PasskeyAuthenticated = false
	} else if claims.UserAuthType == "passkey" {
		cpm.PwAuthenticated = false
		cpm.PasskeyAuthenticated = true
	} else {
		return false
	}

	cpm.CertAuthenticated = performX509auth(req)

	return cpm.CertAuthenticated
}

func PerformAuthentication(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, cpm *metadata.CpMetadata) {
	// Device Authentication
	cpm.CertAuthenticated = performX509auth(req)
	if !cpm.CertAuthenticated {
		return
	}

	// User Authentication
	switch req.URL.Path {
	// Password Authentication
	case "/40d2343b/welcome-page":
		HandleAuthenticationWelcome("", w)
		return
	case "/40d2343b/password-authentication":
		performPasswdAuth(sysLogger, w, req)
		return
	// Passkey Authentication
	case "/40d2343b/passkey-authentication":
		HandlePasskeyAuthentication("", w)
		return
	case "/40d2343b/begin-passkey-register":
		BeginPasskeyRegistration(w, req)
		return
	case "/40d2343b/finish-passkey-register":
		FinishPasskeyRegistration(w, req)
		return
	case "/40d2343b/begin-passkey-login":
		BeginPasskeyLogin(w, req)
		return
	case "/40d2343b/finish-passkey-login":
		FinishPasskeyLogin(sysLogger, w, req)
		return
	default:
		http.Redirect(w, req, "https://"+req.Host+"/40d2343b/welcome-page", http.StatusFound) // 302
		return
	}
}

func setCookieAndFinishAuthentication(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, username, authType string) error {
	// Create JWT
	jwtToken, err := createJWToken(username, authType)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	ztsfcCookie := http.Cookie{
		Name:  "ztsfc_session",
		Value: jwtToken,
		//MaxAge: 86400,
		Path: "/",
	}
	http.SetCookie(w, &ztsfcCookie)

	// TODO: make it user configurable
	// TODO: is there a better solution for the content-length  /body length "bug"?
	req.ContentLength = 0
	//http.Redirect(w, req, "https://"+req.Host+req.URL.String(), http.StatusSeeOther) // 303
	http.Redirect(w, req, "https://"+req.Host, http.StatusSeeOther) // 303
	return nil
}

func createJWToken(username, authType string) (string, error) {
	claims := ZTSFCClaims{
		authType,
		jwt.RegisteredClaims{
			Issuer:    "ztsfc",
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtString, err := token.SignedString([]byte(config.Config.BasicAuth.Session.JwtSigningKey))
	if err != nil {
		return "", fmt.Errorf("basic_auth: createJWToken(): could not sign token: %v", err)
	}

	return jwtString, nil
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

func HandleAuthenticationWelcome(msg string, w http.ResponseWriter) {
	welcomePage := resources.GenerateWelcomePage(msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, welcomePage)
}
