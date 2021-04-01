package main

import (
	"encoding/json"
	"github.com/miguelabate/jwt-go-mabate/jwthandler"
	"github.com/miguelabate/jwt-go-mabate/users"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogin(t *testing.T) {
	//given: user loaded
	users.AddUserWithHashedPass("newuser", "$2a$04$wn0JgGWAEzZ/vuYHl6vCL.oZVxc4uRbiAD4aM0RUBkN1.pIpHjAgS", []string{"CLIENT", "CLIENT2"})

	//when: sign in
	jsonBytes, _ := json.Marshal(jwthandler.Credentials{Username: "newuser", Password: "newpass"})
	request := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(string(jsonBytes)))
	responseRecorder := httptest.NewRecorder()

	jwthandler.SignIn(responseRecorder, request)
	jwtResponseBody := responseRecorder.Body.String()

	//then: auth ok, got jwt token
	assert.NotEqual(t, "", jwtResponseBody, "Jwt token is missing in response")

	//when: doing a request to /welcome that needs auth
	request = httptest.NewRequest(http.MethodPost, "/welcome", nil)
	request.Header.Set("Authorization", "Bearer "+jwtResponseBody)
	responseRecorder = httptest.NewRecorder()

	//do the call
	jwthandler.WithJwtCheck(Welcome, []string{"CLIENT", "ADMIN"}, true)(responseRecorder, request)
	responseBody := responseRecorder.Body.String()

	//then: got a correct response from endpoint. Auth worked fine.
	assert.Equal(t, "Welcome newuser!\n Your roles are: [CLIENT CLIENT2]", responseBody, "Response from /Welcome not expected. Got: %s, Expected: Welcome newuser!\\n Your roles are: [CLIENT CLIENT2]", responseBody)

	//when: doing a request to /welcome that needs auth. But setting required ROLES that the user does not have
	request = httptest.NewRequest(http.MethodPost, "/welcome", nil)
	request.Header.Set("Authorization", "Bearer "+jwtResponseBody)
	responseRecorder = httptest.NewRecorder()

	jwthandler.WithJwtCheck(Welcome, []string{"XXX"}, true)(responseRecorder, request)
	responseBody = responseRecorder.Body.String()

	//then: got a permission error
	assert.Equal(t, "Permission error. User does not have necessary role.", responseBody, "Response body not expected. Got: %s, Expected: Permission error. User does not have necessary role.", responseBody)
	assert.Equal(t, http.StatusUnauthorized, responseRecorder.Code, "Response status should be UnAuthorized")
}
