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

var JwtTokenLifeInMinutes = 5
var JwtTokenRefreshPeriodInSeconds = 30

// key to sign the jwt tokens
var jwtKey = []byte("change_this_key")

// keep a whitelist of jwt tokens that are active. this is lost every time the server restarts
var whiteListTokens = make([]string, 5, 5)

// Create a struct to model credentials (used as request body when creating and login in users)
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// standard jwt claims plus custom data (e.g.: Roles)
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
	expirationTime := time.Now().Add(time.Duration(JwtTokenLifeInMinutes) * time.Minute)
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

	w.Write([]byte(fmt.Sprintf("%s", tokenString)))
}

// wrapper to use for custom endpoints of the actual service that need authentication
// handler: is the actual service function that will handle the request after the authentication/authorization
// neededRoles: list of needed roles by the calling user to get access to the service call
// corsEnabled: mostly for debug. If true will enable cors headers
func WithJwtCheck(handler func(w http.ResponseWriter, r *http.Request, jwtToken *jwt.Token, claims *Claims), neededRoles []string, corsEnabled bool) func(http.ResponseWriter, *http.Request) {

	//decorate the call with the jwt token check and pass the result to the handler function so it can access the token and claims if needed
	return func(w http.ResponseWriter, r *http.Request) {
		if corsEnabled {
			enableCors(&w)
		}
		if r.Method == http.MethodOptions { // so CORS doesnt fail when probing options
			w.WriteHeader(http.StatusOK)
			return
		}
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

// returns a new token if the current is valid and within JwtTokenRefreshPeriodInSeconds seconds of expiration time
func Refresh(w http.ResponseWriter, r *http.Request) {
	tkn, claims, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	// New token is issued only 30 seconds before the old one expires. If a request is made before that time.
	// it will return Ok and the same token.
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > time.Duration(JwtTokenRefreshPeriodInSeconds)*time.Second {
		fmt.Println("not yet", time.Unix(claims.ExpiresAt, 0).Sub(time.Now()))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%s", tkn.Raw))) //just return the old one, still valid
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(time.Duration(JwtTokenLifeInMinutes) * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//add new token to the whitelist
	whiteListTokens = append(whiteListTokens, tokenString)

	w.Write([]byte(fmt.Sprintf("%s", tokenString)))
}

// deletes the jwt token from the current whitelist. Effectively preventing further calls and forcing a signin.
func Logout(w http.ResponseWriter, r *http.Request) {
	tkn, _, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	w.Write([]byte(fmt.Sprintf("LoggedOut")))
}

// checks the token validation from a requests (it takes it from the Authorization header)
// returns the token, the claims and a boolean representing if there was an error (true) or nor (false)
func CheckJwtAuth(w http.ResponseWriter, r *http.Request) (*jwt.Token, *Claims, bool) {
	// We can obtain the session token from the requests Authorization header, which come with every request
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		// If the Authorization header is not set, return an unauthorized status
		w.WriteHeader(http.StatusUnauthorized)
		return &jwt.Token{}, &Claims{}, true
	}

	// Get the JWT string from the Authorization header
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

	//also the token needs to be whitelisted
	if !exists(whiteListTokens, tknStr) {
		w.WriteHeader(http.StatusUnauthorized)
		return tkn, claims, true
	}

	return tkn, claims, false
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

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Add("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
	(*w).Header().Add("Access-Control-Allow-Headers", "*")
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
