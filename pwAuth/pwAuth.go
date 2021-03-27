package pwAuth

import (
	"fmt"
	"local.com/leobrada/ztsfc_http_pep/trustCalculation"
	"net/http"
)

/*
This file realizes a password-authentication mechanism. When a user requests the path "pwAuth", a form is send, where
the user can enter his username and password. For simplicity "test" is the password for every user.
*/

/*
This function is called, when the path pwAuth is called and thus the user wants to authenticate with a password.

@param w: Writer to send a response to the corresponding request
@param req: Request of the password authentication
@param dataSources: Access to databases of the PEP, like the userdatabase

@return username: In case of a successful, the username is provided to the calling instance
@return failedAuth: It is specified, if the authentication was successful
 */
func PasswordAuthentication(w http.ResponseWriter, req *http.Request, dataSources *trustCalculation.DataSources) (username string, failedAuth bool){
	var password string
	form := `<html>
            <body>
            <form action="/" method="post">
            <label for="fname">Username:</label>
            <input type="text" id="username" name="username"><br><br>
            <label for="lname">Password:</label>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Submit">
            </form>
            </body>
            </html>
            `

	// handle post-request, where the username and password should be included
	if req.Method == "POST" {
		if err := req.ParseForm(); err != nil {
			fmt.Println("Parsing Error")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return "", true
		}

		nmbr_of_postvalues := len(req.PostForm)
		if nmbr_of_postvalues != 2 {
			fmt.Println("Too many Post Form Values")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return "",true
		}

		usernamel, exist := req.PostForm["username"]								// Get username from post request
		username = usernamel[0]
		if _, ok:= dataSources.UserDatabase[username]; !ok || !exist{				// Check, if username exists in user database
			fmt.Println("username not present or wrong")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return username, true
		}

		passwordl, exist := req.PostForm["password"]								// Get password from post request
		password = passwordl[0]
		if !exist || password != "test" {											// for simplicity, password is "test" for very user
			fmt.Println("password not present or wrong")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return username, true
		}

		cookie := http.Cookie{														// Create cookie, which is sent in very request of the client to identify the client in the PEP
			Name:   "Username",
			Value:  username,
			MaxAge: 1000,
			Path:   "/",
		}
		http.SetCookie(w, &cookie)
		fmt.Fprintf(w,"Authentication successful")
		return username, false

	} else {
		// send html form to the client, where the client can enter the username and the password
		fmt.Println("only post methods are accepted in this state")
		w.WriteHeader(401)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, form)
		return "",false
	}
}
