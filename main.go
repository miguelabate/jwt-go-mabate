package main

import (
	"github.com/miguelabate/jwt-go-mabate/jwt"
	"github.com/miguelabate/jwt-go-mabate/users"
	"log"
	"net/http"
)

func main() {
	// "Signin" and "Welcome" are the handlers that we will implement
	http.HandleFunc("/signin", jwt.Signin)
	http.HandleFunc("/signup", jwt.Signup)
	http.HandleFunc("/welcome", jwt.Welcome)
	http.HandleFunc("/refresh",jwt. Refresh)
	http.HandleFunc("/logout", jwt.Logout)

	users.LoadUsersFromDB()

	//// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))

	//fmt.Println(hashAndSalt([]byte("password2")))
}
