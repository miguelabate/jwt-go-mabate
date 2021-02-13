package jwthandler

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/miguelabate/jwt-go-mabate/users"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

var jwtKey = []byte("my_secret_key1")

var whiteListTokens = make([]string, 5, 5)

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

//
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.StandardClaims
}

//not secured: to sign up. Creates a user/pass in the db
func Signup(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// check if the user already exists
	if _, ok := users.Users[creds.Username]; ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Error: User %s already exists", creds.Username)))
		return
	}

	//all good. create the user
	users.Users[creds.Username] = hashAndSalt([]byte(creds.Password))
	users.UserRoles[creds.Username] = []string{"CLIENT"} //create default role as CLIENT

	//write to persistence
	users.SaveUser(creds.Username, users.Users[creds.Username], users.UserRoles[creds.Username])

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("User %s created", creds.Username)))
}

//not secured: to sign in
func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := users.Users[creds.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || !comparePasswords(expectedPassword, []byte(creds.Password)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: creds.Username,
		Roles:    users.UserRoles[creds.Username],
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	whiteListTokens = append(whiteListTokens, tokenString)

	w.Write([]byte(fmt.Sprintf("JWT token: %s", tokenString)))
}

func WithJwtCheck(handler func(w http.ResponseWriter, r *http.Request, jwtToken *jwt.Token, claims *Claims), neededRoles []string) func(http.ResponseWriter, *http.Request) {

	//decorate the call with the jwt token check and pass the result to the handler function so it can access the token and claims if needed
	return func(w http.ResponseWriter, r *http.Request) {
		tkn, claims, failedAuth := CheckJwtAuth(w, r)
		if failedAuth {
			w.Write([]byte(fmt.Sprintf("Permission error.")))
			log.Println("Permission error.")
			return
		}

		if !contains(claims.Roles, neededRoles) {
			w.Write([]byte(fmt.Sprintf("Permission error. User does not have necessary role.")))
			log.Println("Permission error. User does not have necessary role.")
			return
		}

		handler(w, r, tkn, claims)
	}
}

// true if any of elements is present in s
func contains(s []string, e []string) bool {
	for _, a := range s {
		for _, b := range e {
			if a == b {
				return true
			}
		}
	}
	return false
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	tkn, claims, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//add new token to the whitelist
	whiteListTokens = append(whiteListTokens, tokenString)

	w.Write([]byte(fmt.Sprintf("JWT token: %s", tokenString)))
}

func Logout(w http.ResponseWriter, r *http.Request) {
	tkn, _, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	w.Write([]byte(fmt.Sprintf("LoggedOut")))
}

func CheckJwtAuth(w http.ResponseWriter, r *http.Request) (*jwt.Token, *Claims, bool) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	// We can obtain the session token from the requests cookies, which come with every request
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		// If the cookie is not set, return an unauthorized status
		w.WriteHeader(http.StatusUnauthorized)
		return &jwt.Token{}, &Claims{}, true
	}

	// Get the JWT string from the cookie
	tknStr := bearerToken[7:]

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return tkn, claims, true
		}
		w.WriteHeader(http.StatusBadRequest)
		return tkn, claims, true
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return tkn, claims, true
	}

	//also the token needs to be whiteliste
	if !exists(whiteListTokens, tknStr) {
		w.WriteHeader(http.StatusUnauthorized)
		return tkn, claims, true
	}
	// (END) The code uptil this point is the same as the first part of the `Welcome` route
	return tkn, claims, false
}

func exists(s []string, r string) bool {
	for _, v := range s {
		if v == r {
			return true
		}
	}
	return false
}

func remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func hashAndSalt(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool { //true: equals
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
