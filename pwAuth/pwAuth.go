package pwAuth

import (
	"fmt"
	"local.com/leobrada/ztsfc_http_pep/trustCalculation"
	"net/http"
)

/*
This file realizes a Password-Authentication mechanism. When a user requests the path "pwAuth", a form is send, where
the user can enter his username and password. For simplicity "test" is the password for every user.
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

		usernamel, exist := req.PostForm["username"]
		username = usernamel[0]
		if _, ok:= dataSources.UserDatabase[username]; !ok || !exist{				// Check, if username exists in user database
			fmt.Println("username not present or wrong")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return username, true
		}

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist || password != "test" {						// for simplicity, password is "test" for very user
			fmt.Println("password not present or wrong")
			w.WriteHeader(401)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, form)
			return username, true
		}

		cookie := http.Cookie{
			Name:   "Username",
			Value:  username,
			MaxAge: 1000,
			Path:   "/",
		}
		http.SetCookie(w, &cookie)
		fmt.Fprintf(w,"Authentication successful")
		return username, false

	} else {
		fmt.Println("only post methods are accepted in this state")
		w.WriteHeader(401)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, form)
		return "",false
	}
}
