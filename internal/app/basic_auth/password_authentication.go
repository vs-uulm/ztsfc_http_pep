// Package basic_auth handles basic authentication for requests to check the
// identity of the requesting user.
package basic_auth

import (
	"crypto/sha512"
	"fmt"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

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
		// JUST FOR DEMONSTRATION
		if failedAttempts > 300 {
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
		if err = setCookieAndFinishAuthentication(sysLogger, w, req, username, "password"); err != nil {
			HandleFormResponse("Internal Error", w)
			sysLogger.Errorf("basic_auth: validPassword(): For user '%s' no session cookie could be created.", username)
			if err := pushAuthFail(sysLogger, username); err != nil {
				sysLogger.Errorf("%v", err)
			}
		}
		return false

	} else {
		// HandleFormResponse("only post methods are accepted in this state", w)
		HandleFormResponse("", w)
		return false
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
		
					h2 {
						font-size: 24px;
						margin: 0 0 10px;
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
		
					input[type="text"],
					input[type="password"],
					#register-username,
					#login-username {
						padding: 12px;
						border-radius: 5px;
						border: none;
						background-color: #f2f2f2;
						width: 100%;
						font-size: 16px;
						margin-bottom: 15px;
					}
		
					button[type="submit"],
					#register-button,
					#login-button {
						padding: 12px 20px;
						border-radius: 5px;
						border: none;
						background-color: #4caf50;
						color: #fff;
						font-size: 16px;
						cursor: pointer;
						transition: background-color 0.3s ease-in-out;
					}
		
					button[type="submit"]:hover,
					#register-button:hover,
					#login-button:hover {
						background-color: #3e8e41;
					}
		
					.passkey-auth {
						margin-top: 30px;
					}
				</style>
			</head>
			<body>
				<div class="container">
					<h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
					<h2>Password Authentication</h2>
					<h3>` + msg + `</h3>
					<form method="POST">
						<label for="username">Username:</label>
						<input type="text" id="username" name="username" required>
						<label for="password">Password:</label>
						<input type="password" id="password" name="password" required>
						<button type="submit">Log In</button>
					</form>
			</body>
		</html>	`

	//	form := `<!DOCTYPE html>
	//	<html>
	//		<head>
	//			<meta charset="UTF-8">
	//			<title>Zero Trust Service Function Chaining Login Portal</title>
	//			<meta name="viewport" content="width=device-width, initial-scale=1">
	//			<style>
	//				body {
	//					font-family: "Segoe UI", "Roboto", sans-serif;
	//					background-color: #f2f2f2;
	//					margin: 0;
	//				}
	//
	//				.container {
	//					background-color: #fff;
	//					border-radius: 5px;
	//					box-shadow: 0 0 20px rgba(0,0,0,0.2);
	//					margin: 50px auto;
	//					padding: 30px;
	//					max-width: 700px;
	//				}
	//
	//				h1 {
	//					font-size: 36px;
	//					margin: 0 0 20px;
	//					text-align: center;
	//					color: #333;
	//				}
	//
	//				h3 {
	//					font-size: 18px;
	//					margin: 0 0 10px;
	//					text-align: center;
	//					color: #f44336;
	//				}
	//
	//				form {
	//					display: flex;
	//					flex-direction: column;
	//					align-items: center;
	//					margin-top: 20px;
	//				}
	//
	//				label {
	//					font-size: 16px;
	//					color: #333;
	//					margin-bottom: 5px;
	//					text-align: left;
	//					display: block;
	//					width: 100%;
	//				}
	//
	//				input[type="text"],
	//				input[type="password"],
	//				#register-username,
	//				#login-username {
	//					padding: 12px;
	//					border-radius: 5px;
	//					border: none;
	//					background-color: #f2f2f2;
	//					width: 100%;
	//					font-size: 16px;
	//					margin-bottom: 15px;
	//				}
	//
	//				button[type="submit"],
	//				#register-button,
	//				#login-button {
	//					padding: 12px 20px;
	//					border-radius: 5px;
	//					border: none;
	//					background-color: #4caf50;
	//					color: #fff;
	//					font-size: 16px;
	//					cursor: pointer;
	//					transition: background-color 0.3s ease-in-out;
	//				}
	//
	//				button[type="submit"]:hover,
	//				#register-button:hover,
	//				#login-button:hover {
	//					background-color: #3e8e41;
	//				}
	//
	//				.passkey-auth {
	//					margin-top: 30px;
	//				}
	//			</style>
	//		</head>
	//		<body>
	//			<div class="container">
	//				<h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
	//				<h1>Password Authentication</h1>
	//				<h3>` + msg + `</h3>
	//				<form method="POST">
	//					<label for="username">Username:</label>
	//					<input type="text" id="username" name="username" required>
	//					<label for="password">Password:</label>
	//					<input type="password" id="password" name="password" required>
	//					<button type="submit">Log In</button>
	//				</form>
	//
	//				<div class="passkey-auth">
	//					<h1>Passkey Authentication</h1>
	//					<h2>Registration</h2>
	//					<input id="register-username" type="text" placeholder="Username">
	//					<button id="register-button">Register</button>
	//
	//					<h2>Login</h2>
	//					<input id="login-username" type="text" placeholder="Username">
	//					<button id="login-button">Login</button>
	//				</div>
	//			</div>
	//
	//			<script>
	//				// Functions to convert base64 to arrayBuffer and vice versa
	//				function base64urlToBuffer(base64url) {
	//					let binary = atob(base64url.replace(/-/g, '+').replace(/_/g, '/'));
	//					let len = binary.length;
	//					let bytes = new Uint8Array(len);
	//					for (let i = 0; i < len; i++) {
	//						bytes[i] = binary.charCodeAt(i);
	//					}
	//					return bytes.buffer;
	//				}
	//
	//				function bufferToBase64url(buffer) {
	//					let binary = '';
	//					let bytes = new Uint8Array(buffer);
	//					for (let i = 0; i < bytes.byteLength; i++) {
	//						binary += String.fromCharCode(bytes[i]);
	//					}
	//					return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	//				}
	//
	//				// Function for WebAuthn Registration
	//				async function register(username) {
	//					// Get challenge from server
	//					const response = await fetch('/begin-register', {
	//						method: 'POST',
	//						headers: {
	//							'Content-Type': 'application/json'
	//						},
	//						body: JSON.stringify({ username })
	//					});
	//					const data = await response.json();
	//
	//					// Convert challenge from base64url to arrayBuffer
	//					data.publicKey.challenge = base64urlToBuffer(data.publicKey.challenge);
	//					data.publicKey.user.id = base64urlToBuffer(data.publicKey.user.id);
	//
	//					// Use WebAuthn API to create a new credential
	//					const credential = await navigator.credentials.create({ publicKey: data.publicKey });
	//
	//					// Post the credential back to the server
	//					const credentialForServer = {
	//						id: credential.id,
	//						type: 'public-key', // This field is needed by the server and its value should be 'public-key' for Webauthn credentials
	//						rawId: bufferToBase64url(credential.rawId),
	//						response: {
	//							clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
	//							attestationObject: bufferToBase64url(credential.response.attestationObject)
	//						},
	//						// Optionally include other fields that the server may be expecting
	//						// transports: ...,
	//						// clientExtensionResults: ...,
	//						// authenticatorAttachment: ...,
	//					};
	//
	//					await fetch('/finish-register', {
	//						method: 'POST',
	//						headers: {
	//							'Content-Type': 'application/json'
	//						},
	//						body: JSON.stringify(credentialForServer)
	//					});
	//				}
	//
	//				// Function for WebAuthn Login
	//				async function login(username) {
	//					// Get challenge from server
	//					const response = await fetch('/begin-login', {
	//						method: 'POST',
	//						headers: {
	//							'Content-Type': 'application/json'
	//						},
	//						body: JSON.stringify({ username })
	//					});
	//					const data = await response.json();
	//
	//					// Convert challenge and allowCredentials.id from base64url to arrayBuffer
	//					data.publicKey.challenge = base64urlToBuffer(data.publicKey.challenge);
	//					for (let cred of data.publicKey.allowCredentials) {
	//						cred.id = base64urlToBuffer(cred.id);
	//					}
	//
	//					// Use WebAuthn API to get an assertion
	//					const assertion = await navigator.credentials.get({ publicKey: data.publicKey });
	//					const assertionForServer = {
	//						id: assertion.id,
	//						type: 'public-key',
	//						rawId: bufferToBase64url(assertion.rawId),
	//						response: {
	//							authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
	//							clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
	//							signature: bufferToBase64url(assertion.response.signature),
	//							userHandle: bufferToBase64url(assertion.response.userHandle)
	//						},
	//					};
	//
	//					await fetch('/finish-login', {
	//						method: 'POST',
	//						headers: {
	//							'Content-Type': 'application/json'
	//						},
	//						body: JSON.stringify(assertionForServer)
	//					});
	//				}
	//
	//				document.getElementById('register-button').addEventListener('click', function () {
	//					const username = document.getElementById('register-username').value;
	//					register(username).then(() => {
	//						console.log('Registration completed');
	//					}).catch((error) => {
	//						console.error('Registration failed', error);
	//					});
	//				});
	//
	//				document.getElementById('login-button').addEventListener('click', function () {
	//					const username = document.getElementById('login-username').value;
	//					login(username).then(() => {
	//						console.log('Login completed');
	//					}).catch((error) => {
	//						console.error('Login failed', error);
	//					});
	//				});
	//			</script>
	//		</body>
	//	</html>`
	//

	//	form := `<!DOCTYPE html>
	//		<html>
	//		  <head>
	//			<meta charset="UTF-8">
	//			<title>Zero Trust Service Function Chaining Login Portal</title>
	//			<meta name="viewport" content="width=device-width, initial-scale=1">
	//			<style>
	//			  body {
	//				font-family: "Segoe UI", "Roboto", sans-serif;
	//				background-color: #f2f2f2;
	//				margin: 0;
	//			  }
	//
	//			  .container {
	//				background-color: #fff;
	//				border-radius: 5px;
	//				box-shadow: 0 0 20px rgba(0,0,0,0.2);
	//				margin: 50px auto;
	//				padding: 30px;
	//				max-width: 700px;
	//			  }
	//
	//			  h1 {
	//				font-size: 36px;
	//				margin: 0 0 20px;
	//				text-align: center;
	//				color: #333;
	//			  }
	//
	//			  h3 {
	//				font-size: 18px;
	//				margin: 0 0 10px;
	//				text-align: center;
	//				color: #f44336;
	//			  }
	//
	//			  form {
	//				display: flex;
	//				flex-direction: column;
	//				align-items: center;
	//				margin-top: 20px;
	//			  }
	//
	//			  label {
	//				font-size: 16px;
	//				color: #333;
	//				margin-bottom: 5px;
	//				text-align: left;
	//				display: block;
	//				width: 100%;
	//			  }
	//
	//			  input[type="text"], input[type="password"] {
	//				padding: 12px;
	//				border-radius: 5px;
	//				border: none;
	//				background-color: #f2f2f2;
	//				width: 100%;
	//				font-size: 16px;
	//				margin-bottom: 15px;
	//			  }
	//
	//			  button[type="submit"] {
	//				padding: 12px 20px;
	//				border-radius: 5px;
	//				border: none;
	//				background-color: #4caf50;
	//				color: #fff;
	//				font-size: 16px;
	//				cursor: pointer;
	//				transition: background-color 0.3s ease-in-out;
	//			  }
	//
	//			  button[type="submit"]:hover {
	//				background-color: #3e8e41;
	//			  }
	//			</style>
	//		  </head>
	//		  <body>
	//			<div class="container">
	//			  <h1>Zero Trust Service Function Chaining<br>Login Portal</h1>
	//			  <h3>` + msg + `</h3>
	//			  <form method="POST">
	//				<label for="username">Username:</label>
	//				<input type="text" id="username" name="username" required>
	//				<label for="password">Password:</label>
	//				<input type="password" id="password" name="password" required>
	//				<button type="submit">Log In</button>
	//			  </form>
	//			</div>
	//		  </body>
	//		</html>
	//        `

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, form)
}
