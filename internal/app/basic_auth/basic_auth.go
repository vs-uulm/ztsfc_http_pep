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

	return true
}

func BasicAuth(sysLogger *logger.Logger, w http.ResponseWriter, req *http.Request, cpm *metadata.CpMetadata) bool {
	// Device Authentication
	cpm.CertAuthenticated = performX509auth(req)
	if !cpm.CertAuthenticated {
		return false
	}

	// User Authentication
	switch req.URL.Path {
	// Password Authentication
	case "/password-authentication":
		cpm.PwAuthenticated = performPasswdAuth(sysLogger, w, req)
		return cpm.PwAuthenticated
	// Passkey Authentication
	case "/passkey-authentication":
		HandlePasskeyAuthentication("", w)
		return false
	case "/begin-passkey-register":
		BeginPasskeyRegistration(w, req)
		return false
	case "/finish-passkey-register":
		FinishPasskeyRegistration(w, req)
		return false
	case "/begin-passkey-login":
		BeginPasskeyLogin(w, req)
		return false
	case "/finish-passkey-login":
		FinishPasskeyLogin(sysLogger, w, req)
		return false
	// All other cases for user without valid session
	default:
		HandleAuthenticationWelcome("", w)
		return false
	}
	//HandleFormResponse("", w)
	//cpm.PwAuthenticated = performPasswdAuth(sysLogger, w, req)
	//if !cpm.PwAuthenticated {
	//	return false
	//}
	//return true
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

func HandleAuthenticationWelcome(msg string, w http.ResponseWriter) {
	response := `<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Zero Trust Service Function Chaining</title>
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

				.button-container {
					display: flex;
					justify-content: center;
					margin-top: 30px;
				}
	
				.button-container button {
					padding: 12px 20px;
					border-radius: 5px;
					border: none;
					background-color: #4caf50;
					color: #fff;
					font-size: 16px;
					cursor: pointer;
					margin: 0 10px;
					transition: background-color 0.3s ease-in-out;
				}
	
				.button-container button:hover {
					background-color: #3e8e41;
				}
			</style>
			<script>
				function navigateToWebsite(path) {
					window.location.href = path;
				}
	
				document.addEventListener('DOMContentLoaded', function() {
					var passwordAuthButton = document.getElementById('password-auth-button');
					var passkeyAuthButton = document.getElementById('passkey-auth-button');
	
					passwordAuthButton.addEventListener('click', function() {
						navigateToWebsite('/password-authentication');
					});
	
					passkeyAuthButton.addEventListener('click', function() {
						navigateToWebsite('/passkey-authentication');
					});
				});
			</script>
		</head>
		<body>
			<div class="container">
				<h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
				<h3>` + msg + `</h3>
				<div class="button-container">
					<button id="password-auth-button">Password Authentication</button>
					<button id="passkey-auth-button">Passkey Authentication</button>
				</div>
			</div>
		</body>
	</html>	
	`

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, response)
}
