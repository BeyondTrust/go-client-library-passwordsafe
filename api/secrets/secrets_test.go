// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements functions to retrieve secrets
// Unit tests for secrets package.
package secrets

import (
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
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

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	response, err := secretObj.SecretGetSecretByPath("path1/path2/", "fake_title", "/", "secrets-safe/secrets")

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

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfig{
		name: "TestSecretGetFileSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`fake_password`))

			if err != nil {
				t.Error("Test case Failed")
			}
		})),
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)
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

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, err := secretObj.GetSecretFlow(secretsPaths, "/")

	if response["oauthgrp_nocert/Test1/Test2/title1"] != testConfig.response {
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

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretPaths := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	secrets, err := secretObj.GetSecretFlow(secretPaths, "/")

	if len(secrets) != 0 {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretGetSecret(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretGetSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`[{"Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "credential_in_sub_3_password",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	response, err := secretObj.GetSecret("path1/path2", "/")

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretGetSecrets(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretGetSecrets",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`[{"Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "credential_in_sub_3_password",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretPaths := []string{"fake/Client", "fake/test_file_1"}
	response, err := secretObj.GetSecrets(secretPaths, "/")

	if response["fake/Client"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlowTechnicalErrorFile(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowTechnicalErrorFile",
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
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBusinessErrorFile(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBusinessErrorFile",
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
				w.WriteHeader(http.StatusConflict)
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowLongSecret(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowLongSecret",
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
				_, err := w.Write([]byte(`fake_password_more_than_30_characteres`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 30)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")

	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}

}

func TestSecretFlowTechnicalErrorCredential(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowTechnicalErrorCredential",
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
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBusinessErrorCredential(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBusinessErrorCredential",
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
				w.WriteHeader(http.StatusConflict)
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBadBody(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBadBody",
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
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}
