package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/miguelabate/jwt-go-mabate/jwthandler"
	"github.com/miguelabate/jwt-go-mabate/users"
	"log"
	"net/http"
)

func main() {
	// provided
	http.HandleFunc("/signin", jwthandler.Signin)
	http.HandleFunc("/signup", jwthandler.Signup)
	http.HandleFunc("/refresh", jwthandler.Refresh)
	http.HandleFunc("/logout", jwthandler.Logout)

	// custom
	http.HandleFunc("/welcome", jwthandler.WithJwtCheck(Welcome, []string{"CLIENT", "ADMIN"}, true))

	users.LoadUsersFromDB()

	//// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))

	//fmt.Println(hashAndSalt([]byte("password2")))
}

func Welcome(w http.ResponseWriter, r *http.Request, jwtToken *jwt.Token, claims *jwthandler.Claims) {
	// username given in the token
	w.Write([]byte(fmt.Sprintf("Welcome %s!\n Your roles are: %s", claims.Username, claims.Roles)))
}
