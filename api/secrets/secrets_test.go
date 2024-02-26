// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements functions to retrieve secrets
// Unit tests for secrets package.
package secrets

import (
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"strings"

	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
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

func TestSecretGetSecretByPath(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	var authenticate, _ = authentication.Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfig{
		name: "TestSecretGetSecretByPath",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`[{"Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.Secret{
			Id:       "9152f5b6-07d6-4955-175a-08db047219ce",
			Title:    "credential_in_sub_3",
			Password: "credential_in_sub_3_password",
		},
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, zapLogger)

	response, err := secretObj.SecretGetSecretByPath("path1/path2", "fake_title", "/", "secrets-safe/secrets")

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretGetFileSecret(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	var authenticate, _ = authentication.Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfig{
		name: "TestSecretGetFileSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`fake_password`))

			if err != nil {
				t.Error("Test case Failed")
			}
		})),
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, zapLogger)
	response, err := secretObj.SecretGetFileSecret("1", testConfig.server.URL)

	if response != "fake_password" {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlow(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	var authenticate, _ = authentication.Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Auth/Signout":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/secrets":
				_, err := w.Write([]byte(`[{"SecretType": "FILE", "Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/secrets/9152f5b6-07d6-4955-175a-08db047219ce/file/download":
				_, err := w.Write([]byte(`fake_password`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_password",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, zapLogger)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	response, err := secretObj.GetSecretFlow(secretsPaths, "/")

	if response["oauthgrp_nocert/Test1"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlow_SecretNotFound(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	var authenticate, _ = authentication.Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Auth/Signout":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/secrets":
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "error SecretGetSecretByPath, Secret was not found: StatusCode: 404 ",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	secretObj, _ := NewSecretObj(*authenticate, zapLogger)

	secretPaths := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	_, err := secretObj.GetSecretFlow(secretPaths, "/")

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}
