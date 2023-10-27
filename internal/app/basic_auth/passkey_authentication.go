package basic_auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
)

var (
	WebAuthnContext *webauthn.WebAuthn
	sessionstore    map[string]*webauthn.SessionData = make(map[string]*webauthn.SessionData)
)

func HandlePasskeyAuthentication(msg string, w http.ResponseWriter) {
	response := `<!DOCTYPE html>
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
						<h2>Passkey Authentication</h2>
						<h3>` + msg + `</h3>
						<div style="margin-top: 40px;"></div>
						<input id="login-username" type="text" placeholder="Username">
						<button id="login-button">Login</button>
						<div style="margin-top: 40px;"></div>
						<input id="register-username" type="text" placeholder="Username">
						<button id="register-button">Register</button>
					</div>
				</div>
	
				<script>
					// Functions to convert base64 to arrayBuffer and vice versa
					function base64urlToBuffer(base64url) {
						let binary = atob(base64url.replace(/-/g, '+').replace(/_/g, '/'));
						let len = binary.length;
						let bytes = new Uint8Array(len);
						for (let i = 0; i < len; i++) {
							bytes[i] = binary.charCodeAt(i);
						}
						return bytes.buffer;
					}
	
					function bufferToBase64url(buffer) {
						let binary = '';
						let bytes = new Uint8Array(buffer);
						for (let i = 0; i < bytes.byteLength; i++) {
							binary += String.fromCharCode(bytes[i]);
						}
						return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
					}
	
					// Function for WebAuthn Registration
					async function register(username) {
						// Get challenge from server
						const response = await fetch('/begin-passkey-register', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify({ username })
						});
						const data = await response.json();
	
						// Convert challenge from base64url to arrayBuffer
						data.publicKey.challenge = base64urlToBuffer(data.publicKey.challenge);
						data.publicKey.user.id = base64urlToBuffer(data.publicKey.user.id);
	
						// Use WebAuthn API to create a new credential
						const credential = await navigator.credentials.create({ publicKey: data.publicKey });
	
						// Post the credential back to the server
						const credentialForServer = {
							id: credential.id,
							type: 'public-key', // This field is needed by the server and its value should be 'public-key' for Webauthn credentials
							rawId: bufferToBase64url(credential.rawId),
							response: {
								clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
								attestationObject: bufferToBase64url(credential.response.attestationObject)
							},
							// Optionally include other fields that the server may be expecting
							// transports: ...,
							// clientExtensionResults: ...,
							// authenticatorAttachment: ...,
						};
	
						await fetch('/finish-passkey-register', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify(credentialForServer)
						});
					}
	
					// Function for WebAuthn Login
					async function login(username) {
						// Get challenge from server
						const response = await fetch('/begin-passkey-login', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify({ username })
						});
						const data = await response.json();
	
						// Convert challenge and allowCredentials.id from base64url to arrayBuffer
						data.publicKey.challenge = base64urlToBuffer(data.publicKey.challenge);
						for (let cred of data.publicKey.allowCredentials) {
							cred.id = base64urlToBuffer(cred.id);
						}
	
						// Use WebAuthn API to get an assertion
						const assertion = await navigator.credentials.get({ publicKey: data.publicKey });
						const assertionForServer = {
							id: assertion.id,
							type: 'public-key',
							rawId: bufferToBase64url(assertion.rawId),
							response: {
								authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
								clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
								signature: bufferToBase64url(assertion.response.signature),
								userHandle: bufferToBase64url(assertion.response.userHandle)
							},
						};
	
						await fetch('/finish-passkey-login', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify(assertionForServer)
						})
							.then(response => {
								// Load the content from the server response
								window.location.href = response.url;
							})
							.catch(error => {
								// Handle any errors that occurred during the fetch or redirection
								console.error('Error:', error);
							});
						
					}
	
					document.getElementById('register-button').addEventListener('click', function () {
						const username = document.getElementById('register-username').value;
						register(username).then(() => {
							console.log('Registration completed');
						}).catch((error) => {
							console.error('Registration failed', error);
						});
					});
	
					document.getElementById('login-button').addEventListener('click', function () {
						const username = document.getElementById('login-username').value;
						login(username).then(() => {
							console.log('Login completed');
						}).catch((error) => {
							console.error('Login failed', error);
						});
					});
				</script>
			</body>
		</html>`

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, response)
}

func BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	// Only POST Methods are supported in this state
	if r.Method != http.MethodPost {
		JSONResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the username as a string
	username := extractUsername(w, r)

	// Check if username exists
	user, ok := config.Config.BasicAuth.Passwd.PasswdListByUsername[username]
	if !ok {
		JSONResponse(w, "User does not exist", http.StatusBadRequest)
		return
	}

	// Check if user already has a passkey
	if user.PasskeyExists() {
		JSONResponse(w, "Passkey for user does already exist", http.StatusBadRequest)
		return
	}

	fmt.Printf("Username: %s, ID: %s\n", user.User, string(user.ID))

	//options, session, err := webAuthnContext.BeginRegistration(user)
	options, sessionData, err := WebAuthnContext.BeginRegistration(user)
	if err != nil {
		JSONResponse(w, "Error creating new user passkey options", http.StatusBadRequest)
		return
	}
	sessionData.UserID = user.ID
	sessionstore[sessionData.Challenge] = sessionData

	// store the sessionData values
	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Failed to read body: %s", err)
	}
	defer r.Body.Close()
	// Create a new reader with the body
	bodyReader := bytes.NewReader(body)

	response, err := protocol.ParseCredentialCreationResponseBody(bodyReader)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "Error while parsing client's CredentialCreationResponseBody", http.StatusBadRequest)
		return
	}

	// TODO: Invalidate challenge
	// Get the session data stored from the function above
	session := sessionstore[response.Response.CollectedClientData.Challenge]

	user, ok := config.Config.BasicAuth.Passwd.PasswdListByID[string(session.UserID)] // Get the user
	if !ok {
		fmt.Printf("Error: user could not restored from active session\n")
	}

	_, err = WebAuthnContext.CreateCredential(user, *session, response)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "Error while creating client's credentials", http.StatusBadRequest)
		return
	}

	// TODO: delete session data?
	// Reset bodyReader to the beginning
	bodyReader.Seek(0, io.SeekStart)
	// Open file for writing the passkey into the file
	file, err := os.OpenFile("/passkeys/"+user.User+".passkey", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "Error while opening passkey file for saving", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Copy body to file
	_, err = io.Copy(file, bodyReader)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "Error while saving passkey", http.StatusBadRequest)
		return
	}

	// If creation was successful, store the credential object
	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	// Only POST Methods are supported in this state
	if r.Method != http.MethodPost {
		JSONResponse(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the username as a string
	username := extractUsername(w, r)

	// Check if username exists
	user, ok := config.Config.BasicAuth.Passwd.PasswdListByUsername[username]
	if !ok {
		JSONResponse(w, "User does not exist", http.StatusBadRequest)
		return
	}

	// Check if user already has a passkey
	if !user.PasskeyExists() {
		JSONResponse(w, "Passkey for user does not exist", http.StatusBadRequest)
		return
	}

	options, session, err := WebAuthnContext.BeginLogin(user)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "User login could not be started", http.StatusBadRequest)
		return
	}

	// store the session values
	session.UserID = user.ID
	sessionstore[session.Challenge] = session

	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishPasskeyLogin(sysLogger *logger.Logger, w http.ResponseWriter, r *http.Request) {
	response, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		JSONResponse(w, "User credentials could not be parsed", http.StatusBadRequest)
		return
	}

	// Get the session data stored from the function above
	session := sessionstore[response.Response.CollectedClientData.Challenge]

	user, ok := config.Config.BasicAuth.Passwd.PasswdListByID[string(session.UserID)] // Get the user
	if !ok {
		JSONResponse(w, "User login could not be finished", http.StatusBadRequest)
		return
	}

	_, err = WebAuthnContext.ValidateLogin(user, *session, response)
	if err != nil {
		JSONResponse(w, "User login credentials could not be validated", http.StatusBadRequest)
		return
	}

	fmt.Println("All Good...")
	// If login was successful, handle next steps
	if err = setCookieAndFinishAuthentication(sysLogger, w, r, user.User, "passkey"); err != nil {
		JSONResponse(w, "User session cookie could not be created", http.StatusBadRequest)
		return
	}
	JSONResponse(w, "Login Success", http.StatusOK)
}

// JSONResponse writes the options and HTTP status code to the http.ResponseWriter
func JSONResponse(w http.ResponseWriter, any interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(any)
	if err != nil {
		// Handle the error if encoding fails
		fmt.Println("Error encoding JSON:", err)
	}
}

func extractUsername(w http.ResponseWriter, r *http.Request) string {
	// Create a temporary struct that holds the username of the JSON data received from client
	var tempUsername struct {
		Username string `json:"username"`
	}

	// Decode the JSON data from the request body
	err := json.NewDecoder(r.Body).Decode(&tempUsername)
	if err != nil {
		JSONResponse(w, err.Error(), http.StatusBadRequest)
		return ""
	}

	// Extract the username as a string
	return tempUsername.Username
}
