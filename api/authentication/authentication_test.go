// Copyright 2024 BeyondTrust. All rights reserved.
// Package authentication implements functions to call Beyondtrust Secret Safe API.
// Unit tests for authentication package.
package authentication

import (
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/utils"
	"log"
	"os"
	"reflect"

	"net/http"
	"net/http/httptest"
	"testing"
)

type UserTestConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignApinResponse
}

type GetTokenConfig struct {
	name     string
	server   *httptest.Server
	response string
}

type GetPasswordSafeAuthenticationConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignApinResponse
}

var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
var httpClient, _ = utils.GetHttpClient(5, true, "", "")
var authenticate, _ = Authenticate(httpClient, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", *logger)

func TestSignOut(t *testing.T) {

	testConfig := UserTestConfig{
		name: "TestSignOut",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(``))
		})),
		response: nil,
	}

	err := authenticate.SignOut(testConfig.server.URL)
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSignAppin(t *testing.T) {

	testConfig := UserTestConfig{
		name: "TestSignAppin",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "Felipe",
		},
	}

	response, err := authenticate.SignAppin(testConfig.server.URL+"/"+"TestSignAppin", "")

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestGetToken(t *testing.T) {

	testConfig := GetTokenConfig{
		name: "TestGetToken",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
			switch r.URL.Path {

			case "/Auth/connect/token":
				w.Write([]byte(`{"access_token": "fake_token", "expires_in": 600, "token_type": "Bearer", "scope": "publicapi"}`))

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_token",
	}

	response, err := authenticate.GetToken(testConfig.server.URL+"/"+"Auth/connect/token", "", "")

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestGetPasswordSafeAuthentication(t *testing.T) {

	testConfig := GetPasswordSafeAuthenticationConfig{
		name: "TestGetPasswordSafeAuthentication",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/connect/token":
				w.Write([]byte(`{"access_token": "fake_token", "expires_in": 600, "token_type": "Bearer", "scope": "publicapi"}`))

			case "/Auth/SignAppIn":
				w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

			default:
				http.NotFound(w, r)
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "Felipe",
		},
	}
	authenticate.ApiUrl = testConfig.server.URL + "/"
	response, err := authenticate.GetPasswordSafeAuthentication()

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}
