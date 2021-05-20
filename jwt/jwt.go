package pep_jwt

import (
    "time"
    "github.com/dgrijalva/jwt-go"
)

func CreateToken() (ss string) {
    mySigningKey := []byte("Alex")

    claims := &jwt.StandardClaims{
        ExpiresAt: time.Now().Add(time.Second * 15).Unix(),
        Issuer: "alex",
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    ss, _ = token.SignedString(mySigningKey)

    return ss
}

//func parseToken(ss string) {
//    //var claims jwt.MapClaims
//    token, _ := jwt.ParseWithClaims(ss, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
//        return []byte("Alex"), nil
//    })
//
//    for key, value := range token.Claims.(jwt.MapClaims) {
//        fmt.Printf("%v:%v\n", key, value)
//    }
//
//}

//func main() {
//    ss := createToken()
//    parseToken(ss)
//}
