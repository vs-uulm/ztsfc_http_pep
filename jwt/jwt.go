package pep_jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

func CreateToken() (ss string) {
	mySigningKey := []byte("Alex")

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Second * 15).Unix(),
		Issuer:    "alex",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ = token.SignedString(mySigningKey)

	return ss
}
