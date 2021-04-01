package jwthandler

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	lestjwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/miguelabate/jwt-go-mabate/users"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

var JwtTokenLifeInMinutes = 5
var JwtTokenRefreshPeriodInSeconds = 30
var GlobalCorsEnabled = true

// key to sign the jwt tokens
var jwtKey = []byte("change_this_key")

// keep a whitelist of jwt tokens that are active. this is lost every time the server restarts
var whiteListTokens = make([]string, 5, 5)

// Create a struct to model credentials (used as request body when creating and login in users)
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type MaJwt struct {
	Raw    string
	Claims MaClaims
	valid  bool
}

type MaClaims struct {
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
	Audience  string   `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	Id        string   `json:"jti,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`
}

//not secured: to sign up. Creates a user/pass in the db
func SignUp(w http.ResponseWriter, r *http.Request) {
	if GlobalCorsEnabled {
		enableCors(&w)
	}

	var credentials Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// check if the user already exists
	if _, ok := users.Users[credentials.Username]; ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("Error: User %s already exists", credentials.Username)))
		return
	}

	//all good. create the user
	users.Users[credentials.Username] = users.HashAndSaltPassword([]byte(credentials.Password))
	users.UserRoles[credentials.Username] = []string{"CLIENT"} //create default role as CLIENT

	//write to persistence
	users.SaveUser(credentials.Username, users.Users[credentials.Username], users.UserRoles[credentials.Username])

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf("User %s created", credentials.Username)))
}

//not secured: to sign in
func SignIn(w http.ResponseWriter, r *http.Request) {
	if GlobalCorsEnabled {
		enableCors(&w)
	}

	var credentials Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := users.Users[credentials.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || !comparePasswords(expectedPassword, []byte(credentials.Password)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(time.Duration(JwtTokenLifeInMinutes) * time.Minute)

	// Create the JWT token and claims, which includes the username and expiry time
	token := lestjwt.New()
	claims := MaClaims{
		Username:  credentials.Username,
		Roles:     users.UserRoles[credentials.Username],
		ExpiresAt: expirationTime.Unix(),
	}

	// set the claims into the token
	addClaims(&token, &claims)

	// Sign the token and generate a payload
	signed, err := lestjwt.Sign(token, jwa.HS256, jwtKey)
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		return
	}

	whiteListTokens = append(whiteListTokens, string(signed))

	// This is what you typically get as a signed JWT from a server
	_, _ = w.Write([]byte(fmt.Sprintf("%s", string(signed))))
}

func addClaims(token *lestjwt.Token, claims *MaClaims) {
	(*token).Set(`username`, claims.Username)
	(*token).Set(`roles`, claims.Roles)
	(*token).Set(lestjwt.ExpirationKey, claims.ExpiresAt)
}

// function that extract some claims of interest from the token and put them in claims
func getClaims(token *lestjwt.Token, claims *MaClaims) {
	if v, ok := (*token).Get(`username`); ok {
		claims.Username = v.(string)
	}
	if v, ok := (*token).Get(`roles`); ok {
		claims.Roles = make([]string, 0)
		for _, message := range v.([]interface{}) {
			claims.Roles = append(claims.Roles, message.(string))
		}
	}
	if v, ok := (*token).Get(lestjwt.ExpirationKey); ok {
		claims.ExpiresAt = v.(time.Time).Unix()
	}
}

// wrapper to use for custom endpoints of the actual service that need authentication
// handler: is the actual service function that will handle the request after the authentication/authorization
// neededRoles: list of needed roles by the calling user to get access to the service call
// corsEnabled: mostly for debug. If true will enable cors headers
func WithJwtCheck(handler func(w http.ResponseWriter, r *http.Request, jwtToken *MaJwt), neededRoles []string, corsEnabled bool) func(http.ResponseWriter, *http.Request) {

	//decorate the call with the jwt token check and pass the result to the handler function so it can access the token and claims if needed
	return func(w http.ResponseWriter, r *http.Request) {
		if corsEnabled {
			enableCors(&w)
		}
		if r.Method == http.MethodOptions { // so CORS doesnt fail when probing options
			w.WriteHeader(http.StatusOK)
			return
		}
		tkn, failedAuth := CheckJwtAuth(w, r)
		if failedAuth {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Permission error.")))
			log.Println("Permission error.")
			return
		}

		if !contains(tkn.Claims.Roles, neededRoles) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Permission error. User does not have necessary role.")))
			log.Println("Permission error. User does not have necessary role.")
			return
		}

		handler(w, r, tkn)
	}
}

// returns a new token if the current is valid and within JwtTokenRefreshPeriodInSeconds seconds of expiration time
func Refresh(w http.ResponseWriter, r *http.Request) {
	if GlobalCorsEnabled {
		enableCors(&w)
	}

	tkn, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	// New token is issued only 30 seconds before the old one expires. If a request is made before that time.
	// it will return Ok and the same token.
	if time.Unix(tkn.Claims.ExpiresAt, 0).Sub(time.Now()) > time.Duration(JwtTokenRefreshPeriodInSeconds)*time.Second {
		fmt.Println("not yet", time.Unix(tkn.Claims.ExpiresAt, 0).Sub(time.Now()))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%s", tkn.Raw))) //just return the old one, still valid
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(time.Duration(JwtTokenLifeInMinutes) * time.Minute)
	tkn.Claims.ExpiresAt = expirationTime.Unix()

	// Sign the token and generate a payload
	token := lestjwt.New()
	addClaims(&token, &tkn.Claims)
	signed, err := lestjwt.Sign(token, jwa.HS256, jwtKey)
	if err != nil {
		fmt.Printf("failed to generate signed payload: %s\n", err)
		return
	}

	//add new token to the whitelist
	whiteListTokens = append(whiteListTokens, string(signed))

	w.Write([]byte(fmt.Sprintf("%s", string(signed))))
}

// deletes the jwt token from the current whitelist. Effectively preventing further calls and forcing a Sign In.
func Logout(w http.ResponseWriter, r *http.Request) {
	if GlobalCorsEnabled {
		enableCors(&w)
	}

	tkn, failedAuth := CheckJwtAuth(w, r)
	if failedAuth {
		return
	}

	//remove old token from list
	whiteListTokens = remove(whiteListTokens, tkn.Raw)

	w.Write([]byte(fmt.Sprintf("LoggedOut")))
}

// checks the token validation from a requests (it takes it from the Authorization header)
// returns the token, the claims and a boolean representing if there was an error (true) or nor (false)
func CheckJwtAuth(w http.ResponseWriter, r *http.Request) (*MaJwt, bool) {
	// We can obtain the session token from the requests Authorization header, which come with every request
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		// If the Authorization header is not set, return an unauthorized status
		w.WriteHeader(http.StatusUnauthorized)
		return &MaJwt{}, true
	}

	// Get the JWT string from the Authorization header
	tknStr := bearerToken[7:]

	// Initialize a new instance of `Claims`
	claims := MaClaims{}

	token, err := lestjwt.Parse([]byte(tknStr), lestjwt.WithVerify(`HS256`, jwtKey))
	if err != nil {
		fmt.Printf("failed to parse payload: %s\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return &MaJwt{}, true
	}

	//get the claims from the token and fill the custom struct
	getClaims(&token, &claims)

	//also the token needs to be whitelisted
	if !exists(whiteListTokens, tknStr) {
		w.WriteHeader(http.StatusUnauthorized)
		return &MaJwt{Raw: tknStr, Claims: claims, valid: false}, true
	}

	return &MaJwt{Raw: tknStr, Claims: claims, valid: true}, false
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

func comparePasswords(hashedPwd string, plainPwd []byte) bool { //true: equals
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
