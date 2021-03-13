package main

import (
	"encoding/json"
	"github.com/miguelabate/jwt-go-mabate/jwthandler"
	"github.com/miguelabate/jwt-go-mabate/users"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogin(t *testing.T) {
	//load users
	users.AddUser("newuser", "$2a$04$wn0JgGWAEzZ/vuYHl6vCL.oZVxc4uRbiAD4aM0RUBkN1.pIpHjAgS", []string{"CLIENT", "CLIENT2"})

	//create request
	jsonBytes, _ := json.Marshal(jwthandler.Credentials{Username: "newuser", Password: "newpass"})
	request := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(string(jsonBytes)))
	responseRecorder := httptest.NewRecorder()

	jwthandler.SignIn(responseRecorder, request)
	jwtResponseBody := responseRecorder.Body.String()

	if jwtResponseBody == "" {
		t.Errorf("No jwt token generated")
	}

	//verify by doing request
	request = httptest.NewRequest(http.MethodPost, "/welcome", nil)
	request.Header.Set("Authorization", "Bearer "+jwtResponseBody)
	responseRecorder = httptest.NewRecorder()

	//call welcome endpoint with check, ok permission
	jwthandler.WithJwtCheck(Welcome, []string{"CLIENT", "ADMIN"}, true)(responseRecorder, request)
	responseBody := responseRecorder.Body.String()
	if responseBody != "Welcome newuser!\n Your roles are: [CLIENT CLIENT2]" {
		t.Errorf("Response from /Welcome not expected. Got: %s, Expected: Welcome newuser!\\n Your roles are: [CLIENT CLIENT2]", responseBody)
	}

	//call welcome endpoint with check, permission fail
	request = httptest.NewRequest(http.MethodPost, "/welcome", nil)
	request.Header.Set("Authorization", "Bearer "+jwtResponseBody)
	responseRecorder = httptest.NewRecorder()

	jwthandler.WithJwtCheck(Welcome, []string{"XXX"}, true)(responseRecorder, request)
	responseBody = responseRecorder.Body.String()
	if responseBody != "Permission error. User does not have necessary role." {
		t.Errorf("Response body not expected. Got: %s, Expected: Permission error. User does not have necessary role.", responseBody)
	}
	if responseRecorder.Code != http.StatusUnauthorized {
		t.Errorf("Response status should be UnAuthorized")
	}
}
