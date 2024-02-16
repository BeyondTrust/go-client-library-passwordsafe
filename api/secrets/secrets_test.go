// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements functions to retrieve secrets
// Unit tests for secrets package.
package secrets

import (
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"log"
	"os"
	"strings"

	"net/http"
	"net/http/httptest"
	"testing"
)

type SecretTestConfig struct {
	name     string
	server   *httptest.Server
	response *entities.Secret
}

type SecretTestConfigStringResponse struct {
	name     string
	server   *httptest.Server
	response string
}

var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
var logLogger = logging.NewLogLogger(logger)
var httpClient, _ = utils.GetHttpClient(5, true, "", "")
var authenticate, _ = authentication.Authenticate(httpClient, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", logLogger, 300)

func TestSecretGetSecretByPath(t *testing.T) {

	testConfig := SecretTestConfig{
		name: "TestSecretGetSecretByPath",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.Write([]byte(`[{"Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
		})),
		response: &entities.Secret{
			Id:       "9152f5b6-07d6-4955-175a-08db047219ce",
			Title:    "credential_in_sub_3",
			Password: "credential_in_sub_3_password",
		},
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, logLogger)

	response, err := secretObj.SecretGetSecretByPath("path1/path2", "fake_title", "/", "secrets-safe/secrets")

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretGetFileSecret(t *testing.T) {

	testConfig := SecretTestConfig{
		name: "TestSecretGetFileSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`fake_password`))
		})),
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, logLogger)
	response, err := secretObj.SecretGetFileSecret("1", testConfig.server.URL)

	if response != "fake_password" {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlow(t *testing.T) {

	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

			case "/Auth/Signout":
				w.Write([]byte(``))

			case "/secrets-safe/secrets":
				w.Write([]byte(`[{"SecretType": "FILE", "Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))

			case "/secrets-safe/secrets/9152f5b6-07d6-4955-175a-08db047219ce/file/download":
				w.Write([]byte(`fake_password`))

			default:
				http.NotFound(w, r)
			}
		})),
		response: "credential_in_sub_3_password",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, logLogger)

	secretList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	response, err := secretObj.GetSecretFlow(secretList, "/")

	if response["oauthgrp_nocert/Test1"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlow_SecretNotFound(t *testing.T) {

	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

			case "/Auth/Signout":
				w.Write([]byte(``))

			case "/secrets-safe/secrets":
				w.Write([]byte(`[]`))

			default:
				http.NotFound(w, r)
			}
		})),
		response: "Error SecretGetSecretByPath, Secret was not found: StatusCode: 404 ",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, logLogger)

	secretList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	_, err := secretObj.GetSecretFlow(secretList, "/")

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}
