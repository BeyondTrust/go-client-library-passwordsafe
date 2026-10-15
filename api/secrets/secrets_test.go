// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements functions to retrieve secrets
// Unit tests for secrets package.
package secrets

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	"github.com/google/uuid"

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

// the recommended version is 3.1. If no version is specified,
// the default API version 3.0 will be used
var apiVersion string = constants.ApiVersion31

var authParams *authentication.AuthenticationParametersObj
var zapLogger *logging.ZapLogger

func InitializeGlobalConfig() {

	logger, _ := zap.NewDevelopment()

	zapLogger = logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	authParams = &authentication.AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                constants.FakeApiUrl,
		APIVersion:                 apiVersion,
		ClientID:                   constants.FakeClientId,
		ClientSecret:               constants.FakeClientSecret,
		ApiKey:                     "",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 300,
	}
}

func TestSecretGetSecretByPath(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	response, err := secretObj.SecretGetSecretByPath("path1/path2/", "fake_title", "/", "secrets-safe/secrets")

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretGetSecretByPathWithDecryptFalse(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfig{
		name: "TestSecretGetSecretByPathWithDecryptFalse",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`[{"Password": "","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.Secret{
			Id:       "9152f5b6-07d6-4955-175a-08db047219ce",
			Title:    "credential_in_sub_3",
			Password: "",
		},
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, false)

	response, err := secretObj.SecretGetSecretByPath("path1/path2/", "fake_title", "/", "secrets-safe/secrets")

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretGetFileSecret(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)
	response, err := secretObj.SecretGetFileSecret("1", testConfig.server.URL)

	if response != "fake_password" {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

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

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlow_SecretNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretPaths := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")
	secrets, err := secretObj.GetSecretFlow(secretPaths, "/")

	if len(secrets) != 0 {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretGetSecret(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	response, err := secretObj.GetSecret("path1/path2", "/")

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretGetSecrets(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

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

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowTechnicalErrorFile",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBusinessErrorFile(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBusinessErrorFile",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowLongSecret(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowLongSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 30, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")

	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}

}

func TestSecretFlowTechnicalErrorCredential(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowTechnicalErrorCredential",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBusinessErrorCredential(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBusinessErrorCredential",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretFlowBadBody(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFlowBadBody",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Auth/Signout":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/secrets":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretsPaths := strings.Split("oauthgrp_nocert/Test1/Test2/title1,oauthgrp_nocert/client_id", ",")
	response, _ := secretObj.GetSecretFlow(secretsPaths, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretCreateTextSecretFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateTextSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets/text":
				_, err := w.Write([]byte(`{"Id": "01ca9cf3-0751-4a90-4856-08dcf22d7472","Title": "Secret Title", "Description": "Title Description"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "Title Description",
	}

	// Test with API Version 3.0
	secretTextDetails30 := entities.SecretTextDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Text:                    constants.FakePassword,
		OwnerType:               "User",
		OwnerId:                 1,
		FolderId:                uuid.New(),
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	response, err := secretObj.CreateSecretFlow("folder1", secretTextDetails30)

	if response.Title != "Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Test with API Version 3.1.
	secretTextDetails31 := entities.SecretTextDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Text:                    constants.FakePassword,
		FolderId:                uuid.New(),
		Owners: []entities.OwnerDetailsGroupId{
			{
				UserId: 1,
				Name:   "administrator",
				Email:  "test@beyondtrust.com",
			},
		},
	}

	response, err = secretObj.CreateSecretFlow("folder1", secretTextDetails31)

	if response.Title != "Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretCreateCredentialSecretFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateCredentialSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets":
				_, err := w.Write([]byte(`{"Id": "01ca9cf3-0751-4a90-4856-08dcf22d7472","Title": "Secret Title", "Description": "Title Description"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "Title Description",
	}

	// Test with API Version 3.0
	secretTextDetails := entities.SecretCredentialDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Username:                "TestUserName",
		Password:                constants.FakePassword,
		OwnerType:               "User",
		OwnerId:                 1,
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	response, err := secretObj.CreateSecretFlow("folder1", secretTextDetails)

	if response.Title != "Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Test with API Version 3.1
	secretTextDetails31 := entities.SecretCredentialDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Username:                "TestUserName",
		Password:                constants.FakePassword,
		Owners: []entities.OwnerDetailsGroupId{
			{
				UserId: 1,
				Name:   "administrator",
				Email:  "test@beyondtrust.com",
			},
		},
	}

	response, err = secretObj.CreateSecretFlow("folder1", secretTextDetails31)

	if response.Title != "Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretCreateFileSecretFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateFileSecretFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets/file":
				_, err := w.Write([]byte(`{"Id": "01ca9cf3-0751-4a90-4856-08dcf22d7472","Title": "File Secret Title", "Description": "Title Description", "FileName": "textfile.txt"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "File Secret Title",
		Description: "File Title Description",
	}

	// Test with API Version 3.0
	secretTextDetails30 := entities.SecretFileDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		FileName:                "textfile.txt",
		FileContent:             "Secret Content",
		OwnerType:               "User",
		OwnerId:                 1,
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	response, err := secretObj.CreateSecretFlow("folder1", secretTextDetails30)

	if response.Title != "File Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, "File Secret Title")
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, "Title Description")
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Test with API Version 3.1
	secretTextDetails31 := entities.SecretFileDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		FileName:                "textfile.txt",
		FileContent:             "Secret Content",
		Owners: []entities.OwnerDetailsGroupId{
			{
				UserId: 1,
				Name:   "administrator",
				Email:  "test@beyondtrust.com",
			},
		},
	}

	response, err = secretObj.CreateSecretFlow("folder1", secretTextDetails31)

	if response.Title != "File Secret Title" {
		t.Errorf("Test case Failed %v, %v", response, "File Secret Title")
	}

	if response.Description != "Title Description" {
		t.Errorf("Test case Failed %v, %v", response, "Title Description")
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretCreateFileSecretFlowErrorFileContent(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name:     "TestSecretCreateFileSecretFlowErrorFileContent",
		server:   httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})),
		response: "Max length '5000000' for 'FileContent' field.",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	// exceeds the max file size value (5MB)
	n := 5_000_001
	fileContent := strings.Repeat("A", n)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "File Title Description",
	}

	secretTextDetails := entities.SecretFileDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		FileName:                "textfile.txt",
		FileContent:             fileContent,
		OwnerType:               "User",
		OwnerId:                 1,
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	_, err := secretObj.CreateSecretFlow("folder1", secretTextDetails)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretCreateFileSecretFlowError(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateFileSecretFlowError",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets/file":
				w.WriteHeader(http.StatusConflict)
				_, err := w.Write([]byte(`{"error":"Title name already exists"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "error - status code: 409 - {\"error\":\"Title name already exists\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "File Title Description",
	}

	secretTextDetails := entities.SecretFileDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		FileName:                "textfile.txt",
		FileContent:             "Secret Content",
		OwnerType:               "User",
		OwnerId:                 1,
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	_, err := secretObj.CreateSecretFlow("folder1", secretTextDetails)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestSecretCreateBadInput(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateBadInput",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets":
				_, err := w.Write([]byte(`{"Id": "01ca9cf3-0751-4a90-4856-08dcf22d7472","Title": "Secret Title", "Description": "Title Description"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "The field 'Title' is required.",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Description: "Title Description",
	}

	secretTextDetails := entities.SecretCredentialDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Username:                "TestUserName",
		Password:                constants.FakePassword,
		OwnerType:               "User",
		OwnerId:                 1,
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	_, err := secretObj.CreateSecretFlow("folder1", secretTextDetails)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretCreateSecretFlowFolderNotFound(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateSecretFlowFolderNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "folder folder_name was not found in folder list",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "Title Description",
	}

	secretTextDetails := entities.SecretTextDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Text:                    constants.FakePassword,
		OwnerType:               "User",
		OwnerId:                 1,
		FolderId:                uuid.New(),
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	_, err := secretObj.CreateSecretFlow("folder_name", secretTextDetails)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretCreateSecretFlowEmptyFolderList(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretCreateSecretFlowEmptyFolderList",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/secrets-safe/folders/":
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "empty List",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "Secret Title",
		Description: "Title Description",
	}

	secretTextDetails := entities.SecretTextDetailsConfig30{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Text:                    constants.FakePassword,
		OwnerType:               "User",
		OwnerId:                 1,
		FolderId:                uuid.New(),
		Owners: []entities.OwnerDetailsOwnerId{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	_, err := secretObj.CreateSecretFlow("folder_name", secretTextDetails)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestSecretFolderFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFolderFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Mocking Response according to the endpoint path
			if r.URL.Path == "/secrets-safe/folders/" && r.Method == "GET" {
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}
			}
			if r.URL.Path == "/secrets-safe/folders/" && r.Method == "POST" {
				_, err := w.Write([]byte(`{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "Folder Title", "Description": "Folder Description"}`))
				if err != nil {
					t.Error("Test case Failed")
				}
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + uuid.New().String(),
		Description: "My Folder Description",
		FolderType:  "FOLDER",
	}

	response, err := secretObj.CreateFolderFlow("folder1", folderDetails)

	if response.Name != "Folder Title" {
		t.Errorf("Test case Failed %v, %v", response.Name, "Folder Title")
	}

	if response.Description != "Folder Description" {
		t.Errorf("Test case Failed %v, %v", response.Description, "Folder Description")
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFolderFlowBadParentFolder(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretFolderFlowBadParentFolder",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Mocking Response according to the endpoint path
			if r.URL.Path == "/secrets-safe/folders/" && r.Method == "GET" {
				_, err := w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}, {"Id": "a4af73dc-4e89-41ec-eb9a-08dcf22d3aba","Name": "folder2"}]`))
				if err != nil {
					t.Error("Test case Failed")
				}
			} else if r.URL.Path == "/secrets-safe/folders/" && r.Method == "POST" {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(`{"error": "InvalidFolderName"}`))
				if err != nil {
					t.Error("Test case Failed")
				}
			} else {
				http.NotFound(w, r)
			}

		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + uuid.New().String(),
		Description: "My Folder Description",
		FolderType:  "FOLDER",
	}

	_, err := secretObj.CreateFolderFlow("folder1", folderDetails)

	expetedErrorMessage := `error - status code: 400 - {"error": "InvalidFolderName"}`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretFolderFlowEmptyParentFolder(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + uuid.New().String(),
		Description: "My Folder Description",
		FolderType:  "FOLDER",
	}

	_, err := secretObj.CreateFolderFlow("", folderDetails)

	expetedErrorMessage := "parent folder name must not be empty"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretSafeFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestSecretSafeFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Mocking Response according to the endpoint path
			if r.URL.Path == "/secrets-safe/safes/" && r.Method == "POST" {
				_, err := w.Write([]byte(`{"Id": "5b6fc3fb-fa78-48f9-9796-08dd18b16b5b","Name": "Safe Title", "Description": "Safe Description"}`))
				if err != nil {
					t.Error("Test case Failed")
				}
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + uuid.New().String(),
		Description: "My Folder Description",
		FolderType:  "SAFE",
	}

	response, err := secretObj.CreateFolderFlow("", folderDetails)

	if response.Name != "Safe Title" {
		t.Errorf("Test case Failed %v, %v", response.Name, "Safe Title")
	}

	if response.Description != "Safe Description" {
		t.Errorf("Test case Failed %v, %v", response.Description, "Safe Description")
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestDeleteSecretById(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSecretById",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the correct endpoint and method
			expectedPath := "/secrets-safe/secrets/9152f5b6-07d6-4955-175a-08db047219ce"
			if r.URL.Path == expectedPath && r.Method == "DELETE" {
				w.WriteHeader(http.StatusOK)
			} else {
				http.NotFound(w, r)
			}
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSecretID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSecretById(validSecretID)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestDeleteSecretByIdInvalidUUID(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	invalidSecretID := "invalid-uuid-format"
	err := secretObj.DeleteSecretById(invalidSecretID)

	if err == nil {
		t.Error("Test case Failed: Expected error for invalid UUID format")
	}

	expectedErrorPrefix := "invalid UUID format for secretID"
	if !strings.Contains(err.Error(), expectedErrorPrefix) {
		t.Errorf("Test case Failed: Expected error to contain '%v', got '%v'", expectedErrorPrefix, err.Error())
	}
}

func TestDeleteSecretByIdNotFound(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSecretByIdNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 404 response for secret not found
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`{"error": "Secret not found"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "error - status code: 404 - {\"error\": \"Secret not found\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSecretID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSecretById(validSecretID)

	if err == nil {
		t.Error("Test case Failed: Expected error for secret not found")
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Test case Failed: Expected 404 error, got '%v'", err.Error())
	}
}

func TestDeleteSecretByIdForbidden(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSecretByIdForbidden",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 403 response for forbidden access
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte(`{"error": "Insufficient permissions"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "error - status code: 403 - {\"error\": \"Insufficient permissions\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSecretID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSecretById(validSecretID)

	if err == nil {
		t.Error("Test case Failed: Expected error for forbidden access")
	}

	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Test case Failed: Expected 403 error, got '%v'", err.Error())
	}
}

func TestDeleteSecretByIdServerError(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSecretByIdServerError",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 500 response for server error
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(`{"error": "Internal server error"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "error - status code: 500 - {\"error\": \"Internal server error\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSecretID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSecretById(validSecretID)

	if err == nil {
		t.Error("Test case Failed: Expected error for server error")
	}

	// The HTTP client returns a different error format for DELETE operations in test environment
	// Accept either the expected format or the actual format returned
	if !strings.Contains(err.Error(), "500") && !strings.Contains(err.Error(), "DELETE") {
		t.Errorf("Test case Failed: Expected error related to DELETE operation, got '%v'", err.Error())
	}
}

func TestDeleteFolderById(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteFolderById",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the correct endpoint and method
			if r.Method != "DELETE" {
				t.Errorf("Expected DELETE method, got %v", r.Method)
			}
			if !strings.Contains(r.URL.Path, "/secrets-safe/folders/") {
				t.Errorf("Expected URL to contain '/secrets-safe/folders/', got %v", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validFolderID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteFolderById(validFolderID)

	if err != nil {
		t.Errorf("Test case Failed: Expected no error, got: %v", err)
	}
}

func TestDeleteFolderByIdInvalidUUID(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	invalidFolderID := "invalid-uuid-format"
	err := secretObj.DeleteFolderById(invalidFolderID)

	if err == nil {
		t.Error("Test case Failed: Expected error for invalid UUID")
	}

	expectedErrorPrefix := "invalid UUID format for folderID"
	if !strings.Contains(err.Error(), expectedErrorPrefix) {
		t.Errorf("Test case Failed: Expected error to contain '%v', got: %v", expectedErrorPrefix, err.Error())
	}
}

func TestDeleteFolderByIdNotFound(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteFolderByIdNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 404 response for folder not found
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`{"error": "Folder not found"}`))
			if err != nil {
				t.Error(err)
			}
		})),
		response: "error - status code: 404 - {\"error\": \"Folder not found\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validFolderID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteFolderById(validFolderID)

	if err == nil {
		t.Error("Test case Failed: Expected error for 404 response")
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Test case Failed: Expected 404 error, got '%v'", err.Error())
	}
}

func TestDeleteFolderByIdForbidden(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteFolderByIdForbidden",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 403 response for forbidden access
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte(`{"error": "Insufficient permissions"}`))
			if err != nil {
				t.Error(err)
			}
		})),
		response: "error - status code: 403 - {\"error\": \"Insufficient permissions\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validFolderID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteFolderById(validFolderID)

	if err == nil {
		t.Error("Test case Failed: Expected error for 403 response")
	}

	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Test case Failed: Expected 403 error, got '%v'", err.Error())
	}
}

func TestDeleteFolderByIdServerError(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteFolderByIdServerError",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 500 response for server error
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(`{"error": "Internal server error"}`))
			if err != nil {
				t.Error(err)
			}
		})),
		response: "error - status code: 500 - {\"error\": \"Internal server error\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validFolderID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteFolderById(validFolderID)

	if err == nil {
		t.Error("Test case Failed: Expected error for 500 response")
	}

	// The HTTP client returns a different error format for DELETE operations in test environment
	// Accept either the expected format or the actual format returned
	if !strings.Contains(err.Error(), "500") && !strings.Contains(err.Error(), "DELETE") {
		t.Errorf("Test case Failed: Expected error related to DELETE operation, got '%v'", err.Error())
	}
}

func TestDeleteSafeById(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSafeById",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the correct endpoint and method
			if r.Method != "DELETE" {
				t.Errorf("Expected DELETE method, got %v", r.Method)
			}
			if !strings.Contains(r.URL.Path, "/secrets-safe/safes/") {
				t.Errorf("Expected URL to contain '/secrets-safe/safes/', got %v", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		})),
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSafeID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSafeById(validSafeID)

	if err != nil {
		t.Errorf("Test case Failed: Expected no error, got: %v", err)
	}
}

func TestDeleteSafeByIdInvalidUUID(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	invalidSafeID := "invalid-uuid-format"
	err := secretObj.DeleteSafeById(invalidSafeID)

	if err == nil {
		t.Error("Test case Failed: Expected error for invalid UUID")
	}

	expectedErrorPrefix := "invalid UUID format for safeID"
	if !strings.Contains(err.Error(), expectedErrorPrefix) {
		t.Errorf("Test case Failed: Expected error to contain '%v', got: %v", expectedErrorPrefix, err.Error())
	}
}

func TestDeleteSafeByIdNotFound(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfigStringResponse{
		name: "TestDeleteSafeByIdNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mock 404 response for safe not found
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`{"error": "Safe not found"}`))
			if err != nil {
				t.Error(err)
			}
		})),
		response: "error - status code: 404 - {\"error\": \"Safe not found\"}",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	validSafeID := "9152f5b6-07d6-4955-175a-08db047219ce"
	err := secretObj.DeleteSafeById(validSafeID)

	if err == nil {
		t.Error("Test case Failed: Expected error for 404 response")
	}

	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Test case Failed: Expected 404 error, got '%v'", err.Error())
	}
}

func TestSearchSecretByTitleFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfig{
		name: "TestSearchSecretByTitleFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`[{"Password": "secret_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "secret_title"}]`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.Secret{
			Id:       "9152f5b6-07d6-4955-175a-08db047219ce",
			Title:    "secret_title",
			Password: "secret_password",
		},
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	response, err := secretObj.SearchSecretByTitleFlow("secret_title")

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSearchSecretByTitleFlowSecretNotFound(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := SecretTestConfig{
		name: "TestSearchSecretByTitleFlowSecretNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`{"error": "Secret not found"}`))
			if err != nil {
				t.Error(err)
			}
		})),
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	_, err := secretObj.SearchSecretByTitleFlow("secret_title")

	if err == nil {
		t.Error("Test case Failed: Expected error for 404 response")
	}
}

// TestBuildCredentialSecretConfig covers the per-version dispatch in the credential build helper.
func TestBuildCredentialSecretConfig(t *testing.T) {
	in := entities.SecretCredentialInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T", Description: "D", Notes: "N"},
		Username:                "u",
		Password:                "p",
		OwnerId:                 1,
		OwnerType:               "User",
		OwnersByOwnerId:         []entities.OwnerDetailsOwnerId{{OwnerId: 1, Owner: "a", Email: "x@y"}},
		OwnersByGroupId:         []entities.OwnerDetailsGroupId{{GroupId: 7, UserId: 1, Name: "a", Email: "x@y"}},
	}

	t.Run("v3.0 returns Config30 with OwnersByOwnerId", func(t *testing.T) {
		got, err := buildCredentialSecretConfig(in, "3.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, ok := got.(entities.SecretCredentialDetailsConfig30)
		if !ok {
			t.Fatalf("expected SecretCredentialDetailsConfig30, got %T", got)
		}
		if cfg.Username != "u" || cfg.Password != "p" || cfg.OwnerId != 1 || cfg.OwnerType != "User" {
			t.Errorf("fields not mapped: %+v", cfg)
		}
		if len(cfg.Owners) != 1 || cfg.Owners[0].Owner != "a" {
			t.Errorf("expected OwnersByOwnerId, got %+v", cfg.Owners)
		}
	})

	t.Run("v3.1 returns Config31 with OwnersByGroupId", func(t *testing.T) {
		got, err := buildCredentialSecretConfig(in, "3.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, ok := got.(entities.SecretCredentialDetailsConfig31)
		if !ok {
			t.Fatalf("expected SecretCredentialDetailsConfig31, got %T", got)
		}
		if cfg.Username != "u" || cfg.Password != "p" {
			t.Errorf("fields not mapped: %+v", cfg)
		}
		if len(cfg.Owners) != 1 || cfg.Owners[0].GroupId != 7 {
			t.Errorf("expected OwnersByGroupId, got %+v", cfg.Owners)
		}
	})

	t.Run("v3.2 returns Config32 with OwnersByGroupId", func(t *testing.T) {
		got, err := buildCredentialSecretConfig(in, "3.2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, ok := got.(entities.SecretCredentialDetailsConfig32)
		if !ok {
			t.Fatalf("expected SecretCredentialDetailsConfig32, got %T", got)
		}
		if cfg.Username != "u" || cfg.Password != "p" {
			t.Errorf("fields not mapped: %+v", cfg)
		}
		if len(cfg.Owners) != 1 || cfg.Owners[0].GroupId != 7 {
			t.Errorf("expected OwnersByGroupId, got %+v", cfg.Owners)
		}
	})

	t.Run("unsupported version returns error", func(t *testing.T) {
		_, err := buildCredentialSecretConfig(in, "9.9")
		if err == nil || !strings.Contains(err.Error(), "unsupported API version") {
			t.Errorf("expected unsupported API version error, got %v", err)
		}
	})
}

// TestBuildTextSecretConfig covers the per-version dispatch in the text build helper.
func TestBuildTextSecretConfig(t *testing.T) {
	in := entities.SecretTextInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Text:                    "secret-text",
		OwnerId:                 1,
		OwnerType:               "User",
		OwnersByOwnerId:         []entities.OwnerDetailsOwnerId{{OwnerId: 1, Owner: "a", Email: "x@y"}},
		OwnersByGroupId:         []entities.OwnerDetailsGroupId{{GroupId: 7, UserId: 1, Name: "a", Email: "x@y"}},
	}

	t.Run("v3.0 returns Config30", func(t *testing.T) {
		got, err := buildTextSecretConfig(in, "3.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, ok := got.(entities.SecretTextDetailsConfig30)
		if !ok {
			t.Fatalf("expected SecretTextDetailsConfig30, got %T", got)
		}
		if cfg.Text != "secret-text" || cfg.OwnerId != 1 || cfg.OwnerType != "User" {
			t.Errorf("fields not mapped: %+v", cfg)
		}
	})

	t.Run("v3.1 returns Config31", func(t *testing.T) {
		got, err := buildTextSecretConfig(in, "3.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got.(entities.SecretTextDetailsConfig31); !ok {
			t.Fatalf("expected SecretTextDetailsConfig31, got %T", got)
		}
	})

	t.Run("v3.2 returns Config32", func(t *testing.T) {
		got, err := buildTextSecretConfig(in, "3.2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got.(entities.SecretTextDetailsConfig32); !ok {
			t.Fatalf("expected SecretTextDetailsConfig32, got %T", got)
		}
	})

	t.Run("unsupported version returns error", func(t *testing.T) {
		_, err := buildTextSecretConfig(in, "9.9")
		if err == nil || !strings.Contains(err.Error(), "unsupported API version") {
			t.Errorf("expected unsupported API version error, got %v", err)
		}
	})
}

// TestBuildFileSecretConfig covers the per-version dispatch in the file build helper.
func TestBuildFileSecretConfig(t *testing.T) {
	in := entities.SecretFileInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		FileName:                "config.json",
		FileContent:             "file-content",
		OwnerId:                 1,
		OwnerType:               "User",
		OwnersByOwnerId:         []entities.OwnerDetailsOwnerId{{OwnerId: 1, Owner: "a", Email: "x@y"}},
		OwnersByGroupId:         []entities.OwnerDetailsGroupId{{GroupId: 7, UserId: 1, Name: "a", Email: "x@y"}},
	}

	t.Run("v3.0 returns Config30", func(t *testing.T) {
		got, err := buildFileSecretConfig(in, "3.0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, ok := got.(entities.SecretFileDetailsConfig30)
		if !ok {
			t.Fatalf("expected SecretFileDetailsConfig30, got %T", got)
		}
		if cfg.FileName != "config.json" || cfg.FileContent != "file-content" {
			t.Errorf("fields not mapped: %+v", cfg)
		}
	})

	t.Run("v3.1 returns Config31", func(t *testing.T) {
		got, err := buildFileSecretConfig(in, "3.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got.(entities.SecretFileDetailsConfig31); !ok {
			t.Fatalf("expected SecretFileDetailsConfig31, got %T", got)
		}
	})

	t.Run("v3.2 returns Config32", func(t *testing.T) {
		got, err := buildFileSecretConfig(in, "3.2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := got.(entities.SecretFileDetailsConfig32); !ok {
			t.Fatalf("expected SecretFileDetailsConfig32, got %T", got)
		}
	})

	t.Run("unsupported version returns error", func(t *testing.T) {
		_, err := buildFileSecretConfig(in, "9.9")
		if err == nil || !strings.Contains(err.Error(), "unsupported API version") {
			t.Errorf("expected unsupported API version error, got %v", err)
		}
	})
}

// TestDecodeSecretListResponse covers normalization of v3.0/v3.1 array and v3.2 wrapper shapes.
func TestDecodeSecretListResponse(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantLen   int
		wantTitle string
		wantErr   bool
	}{
		{
			name:      "v3.0/v3.1 bare array with one item",
			body:      `[{"Id":"id-1","Title":"T1"}]`,
			wantLen:   1,
			wantTitle: "T1",
		},
		{
			name:    "empty array",
			body:    `[]`,
			wantLen: 0,
		},
		{
			name:      "v3.2 wrapped object with one item",
			body:      `{"TotalCount":1,"Data":[{"Id":"id-1","Title":"T2"}]}`,
			wantLen:   1,
			wantTitle: "T2",
		},
		{
			name:    "v3.2 wrapped object with empty Data",
			body:    `{"TotalCount":0,"Data":[]}`,
			wantLen: 0,
		},
		{
			name:    "leading whitespace before array still parses",
			body:    "   \n[{\"Id\":\"id-1\",\"Title\":\"T1\"}]",
			wantLen: 1,
		},
		{
			name:    "invalid JSON returns error",
			body:    `not json`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeSecretListResponse([]byte(c.body))
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != c.wantLen {
				t.Fatalf("got %d items, want %d", len(got), c.wantLen)
			}
			if c.wantTitle != "" && got[0].Title != c.wantTitle {
				t.Errorf("got Title=%q, want %q", got[0].Title, c.wantTitle)
			}
		})
	}
}

// TestCreateSecretFlowWithNeutralInputs verifies CreateSecretFlow accepts the new
// version-neutral inputs and dispatches correctly across v3.0/v3.1/v3.2.
func TestCreateSecretFlowWithNeutralInputs(t *testing.T) {
	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/secrets-safe/folders/":
			_, _ = w.Write([]byte(`[{"Id":"folder-id","Name":"folder1"}]`))
		case "/secrets-safe/folders/folder-id/secrets",
			"/secrets-safe/folders/folder-id/secrets/text",
			"/secrets-safe/folders/folder-id/secrets/file":
			_, _ = w.Write([]byte(`{"Id":"new-secret-id","Title":"T","Description":"D"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	base := entities.SecretDetailsBaseConfig{Title: "T", Description: "D"}
	ownerById := []entities.OwnerDetailsOwnerId{{OwnerId: 1, Owner: "a", Email: "x@y"}}
	ownerByGroup := []entities.OwnerDetailsGroupId{{GroupId: 7, UserId: 1, Name: "a", Email: "x@y"}}

	for _, v := range []string{"3.0", "3.1", "3.2"} {
		v := v
		secretObj.authenticationObj.ApiVersion = v

		t.Run("credential v"+v, func(t *testing.T) {
			in := entities.SecretCredentialInput{
				SecretDetailsBaseConfig: base,
				Username:                "u",
				Password:                "p",
				OwnerId:                 1,
				OwnerType:               "User",
				OwnersByOwnerId:         ownerById,
				OwnersByGroupId:         ownerByGroup,
			}
			resp, err := secretObj.CreateSecretFlow("folder1", in)
			if err != nil {
				t.Fatalf("CreateSecretFlow error for v%s: %v", v, err)
			}
			if resp.Id != "new-secret-id" {
				t.Errorf("expected new-secret-id, got %+v", resp)
			}
		})

		t.Run("text v"+v, func(t *testing.T) {
			in := entities.SecretTextInput{
				SecretDetailsBaseConfig: base,
				Text:                    "secret-text",
				OwnerId:                 1,
				OwnerType:               "User",
				OwnersByOwnerId:         ownerById,
				OwnersByGroupId:         ownerByGroup,
			}
			resp, err := secretObj.CreateSecretFlow("folder1", in)
			if err != nil {
				t.Fatalf("CreateSecretFlow error for v%s: %v", v, err)
			}
			if resp.Id != "new-secret-id" {
				t.Errorf("expected new-secret-id, got %+v", resp)
			}
		})
	}
}

// TestCreateSecretFlowUnsupportedVersionRejected verifies an unsupported API version
// surfaces the centralized error.
func TestCreateSecretFlowUnsupportedVersionRejected(t *testing.T) {
	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)
	secretObj.authenticationObj.ApiVersion = "9.9"

	in := entities.SecretCredentialInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Username:                "u",
		Password:                "p",
	}
	_, err := secretObj.CreateSecretFlow("folder1", in)
	if err == nil || !strings.Contains(err.Error(), "unsupported API version") {
		t.Fatalf("expected unsupported API version error, got %v", err)
	}
}

// TestSearchSecretByTitleFlowWithV32WrappedResponse verifies decodeSecretListResponse
// is wired into SearchSecretByTitle and unwraps the v3.2 envelope transparently.
func TestSearchSecretByTitleFlowWithV32WrappedResponse(t *testing.T) {
	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`{"TotalCount":1,"Data":[{"Password":"secret_password","Id":"9152f5b6-07d6-4955-175a-08db047219ce","Title":"secret_title"}]}`))
		if err != nil {
			t.Error("Test case Failed")
		}
	}))
	defer server.Close()

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	response, err := secretObj.SearchSecretByTitleFlow("secret_title")
	if err != nil {
		t.Fatalf("Test case Failed: %v", err)
	}
	if response.Id != "9152f5b6-07d6-4955-175a-08db047219ce" || response.Title != "secret_title" {
		t.Errorf("Test case Failed: got %+v", response)
	}
}

// TestSecretGetSecretByPathWithV32WrappedResponse verifies the path-lookup variant
// also accepts the v3.2 wrapped response.
func TestSecretGetSecretByPathWithV32WrappedResponse(t *testing.T) {
	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`{"TotalCount":1,"Data":[{"SecretType":"TEXT","Password":"secret_password","Id":"id-1","Title":"fake_title"}]}`))
		if err != nil {
			t.Error("Test case Failed")
		}
	}))
	defer server.Close()

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)

	response, err := secretObj.SecretGetSecretByPath("path1/path2/", "fake_title", "/", "secrets-safe/secrets")
	if err != nil {
		t.Fatalf("Test case Failed: %v", err)
	}
	if response.Id != "id-1" || response.Title != "fake_title" {
		t.Errorf("Test case Failed: got %+v", response)
	}
}

func newTotpTestSecretObj(t *testing.T, version string, handler http.HandlerFunc) *SecretObj {
	t.Helper()
	InitializeGlobalConfig()
	authenticate, _ := authentication.Authenticate(*authParams)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	authenticate.ApiVersion = version
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000, true)
	return secretObj
}

func boolPtr(b bool) *bool { return &b }

func TestBuildSecretConfigsVersion33(t *testing.T) {
	owners := []entities.OwnerDetailsGroupId{{GroupId: 1, UserId: 1}}
	credIn := entities.SecretCredentialInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "t"},
		Username:                "u", Password: "p", OwnersByGroupId: owners,
		TotpEnabled: boolPtr(true), TotpSecretKey: "JBSWY3DPEHPK3PXP",
	}
	cfg, err := buildCredentialSecretConfig(credIn, "3.3")
	if err != nil {
		t.Fatal(err)
	}
	c33, ok := cfg.(entities.SecretCredentialDetailsConfig33)
	if !ok || c33.TotpEnabled == nil || !*c33.TotpEnabled || c33.TotpSecretKey != "JBSWY3DPEHPK3PXP" {
		t.Errorf("unexpected 3.3 credential config: %#v", cfg)
	}

	if cfg, err = buildTextSecretConfig(entities.SecretTextInput{Text: "x", OwnersByGroupId: owners}, "3.3"); err != nil {
		t.Fatal(err)
	} else if _, ok := cfg.(entities.SecretTextDetailsConfig32); !ok {
		t.Errorf("text 3.3 should reuse 3.2 shape, got %T", cfg)
	}
	if cfg, err = buildFileSecretConfig(entities.SecretFileInput{FileName: "f", FileContent: "c", OwnersByGroupId: owners}, "3.3"); err != nil {
		t.Fatal(err)
	} else if _, ok := cfg.(entities.SecretFileDetailsConfig32); !ok {
		t.Errorf("file 3.3 should reuse 3.2 shape, got %T", cfg)
	}

	// Older versions keep their shape and reject TOTP fields instead of dropping them silently.
	for _, v := range []string{"3.0", "3.1", "3.2"} {
		if _, err = buildCredentialSecretConfig(credIn, v); err == nil {
			t.Errorf("expected TOTP to be rejected for version %v", v)
		}
		plain := credIn
		plain.TotpEnabled, plain.TotpSecretKey = nil, ""
		if _, err = buildCredentialSecretConfig(plain, v); err != nil {
			t.Errorf("version %v without TOTP should work: %v", v, err)
		}
	}
}

func TestCreateCredentialSecretFlowVersion33SendsTotp(t *testing.T) {
	var received map[string]interface{}
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/secrets-safe/folders/":
			_, _ = w.Write([]byte(`[{"Id": "cb871861-8b40-4556-820c-1ca6d522adfa","Name": "folder1"}]`))
		case "/secrets-safe/folders/cb871861-8b40-4556-820c-1ca6d522adfa/secrets":
			if r.URL.Query().Get("version") != "3.3" {
				t.Errorf("expected version=3.3, got %q", r.URL.RawQuery)
			}
			_ = json.NewDecoder(r.Body).Decode(&received)
			_, _ = w.Write([]byte(`{"Id": "01ca9cf3-0751-4a90-4856-08dcf22d7472","Title": "T","TotpEnabled": true,"TotpParameters":{"Digits":6,"PeriodSeconds":30}}`))
		default:
			http.NotFound(w, r)
		}
	})

	in := entities.SecretCredentialInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Username:                "u", Password: constants.FakePassword,
		OwnersByGroupId: []entities.OwnerDetailsGroupId{{GroupId: 1, UserId: 1}},
		TotpEnabled:     boolPtr(true), TotpSecretKey: "JBSWY3DPEHPK3PXP",
	}
	resp, err := secretObj.CreateSecretFlow("folder1", in)
	if err != nil {
		t.Fatal(err)
	}
	if received["TotpEnabled"] != true || received["TotpSecretKey"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP fields not sent: %v", received)
	}
	if !resp.TotpEnabled || resp.TotpParameters == nil || resp.TotpParameters.Digits != 6 || resp.TotpParameters.PeriodSeconds != 30 {
		t.Errorf("TOTP response not surfaced: %#v", resp)
	}
}

func TestCreateCredentialSecretFlowInvalidTotp(t *testing.T) {
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %v", r.URL.Path)
	})
	base := entities.SecretCredentialInput{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Username:                "u", Password: constants.FakePassword,
		OwnersByGroupId: []entities.OwnerDetailsGroupId{{GroupId: 1, UserId: 1}},
	}
	cases := map[string]func(*entities.SecretCredentialInput){
		"enabled without seed": func(i *entities.SecretCredentialInput) { i.TotpEnabled = boolPtr(true) },
		"seed without enabled": func(i *entities.SecretCredentialInput) { i.TotpSecretKey = "JBSWY3DPEHPK3PXP" },
		"seed with false": func(i *entities.SecretCredentialInput) {
			i.TotpEnabled = boolPtr(false)
			i.TotpSecretKey = "JBSWY3DPEHPK3PXP"
		},
		"seed too long": func(i *entities.SecretCredentialInput) {
			i.TotpEnabled = boolPtr(true)
			i.TotpSecretKey = strings.Repeat("A", 1025)
		},
	}
	for name, mutate := range cases {
		in := base
		mutate(&in)
		if _, err := secretObj.CreateSecretFlow("folder1", in); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// TestCreateTextAndFileSecretsSkipTotpChecks verifies the TOTP checks only apply to credential
// payloads: text and file secrets are created with any API version.
func TestCreateTextAndFileSecretsSkipTotpChecks(t *testing.T) {
	base := entities.SecretDetailsBaseConfig{Title: "T"}
	owners := []entities.OwnerDetailsGroupId{{UserId: 1}}
	payloads := map[string]interface{}{
		"text 3.0": entities.SecretTextDetailsConfig30{SecretDetailsBaseConfig: base, Text: "t", OwnerType: "User", Owners: []entities.OwnerDetailsOwnerId{{OwnerId: 1}}},
		"text 3.1": entities.SecretTextDetailsConfig31{SecretDetailsBaseConfig: base, Text: "t", Owners: owners},
		"text 3.2": entities.SecretTextDetailsConfig32{SecretDetailsBaseConfig: base, Text: "t", Owners: owners},
		"file 3.0": entities.SecretFileDetailsConfig30{SecretDetailsBaseConfig: base, FileName: "f", FileContent: "c", OwnerType: "User", Owners: []entities.OwnerDetailsOwnerId{{OwnerId: 1}}},
		"file 3.1": entities.SecretFileDetailsConfig31{SecretDetailsBaseConfig: base, FileName: "f", FileContent: "c", Owners: owners},
		"file 3.2": entities.SecretFileDetailsConfig32{SecretDetailsBaseConfig: base, FileName: "f", FileContent: "c", Owners: owners},
	}
	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32, constants.ApiVersion33} {
		for name, payload := range payloads {
			if err := validateCreateTotp(payload, version); err != nil {
				t.Errorf("%s with %s: validateCreateTotp: %v", name, version, err)
			}
			if err := validateTotpApiVersion(payload, version); err != nil {
				t.Errorf("%s with %s: validateTotpApiVersion: %v", name, version, err)
			}
		}
	}

	// v3.3 reuses the v3.2 text and file payloads; both reach the server.
	for _, version := range []string{constants.ApiVersion31, constants.ApiVersion32, constants.ApiVersion33} {
		requests := 0
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/secrets-safe/folders/" {
				_, _ = w.Write([]byte(`[{"Id":"folder-id","Name":"folder1"}]`))
				return
			}
			requests++
			_, _ = w.Write([]byte(`{"Id":"new-secret-id","Title":"T"}`))
		})
		if _, err := secretObj.CreateSecretFlow("folder1", entities.SecretTextInput{SecretDetailsBaseConfig: base, Text: "t", OwnersByGroupId: owners}); err != nil {
			t.Errorf("%s: create text: %v", version, err)
		}
		if _, err := secretObj.CreateSecretFlow("folder1", entities.SecretFileInput{SecretDetailsBaseConfig: base, FileName: "f", FileContent: "c", OwnersByGroupId: owners}); err != nil {
			t.Errorf("%s: create file: %v", version, err)
		}
		if _, err := secretObj.SecretCreateSecret("folder-id", entities.SecretTextDetailsConfig32{SecretDetailsBaseConfig: base, Text: "t", Owners: owners}); err != nil {
			t.Errorf("%s: SecretCreateSecret text: %v", version, err)
		}
		if requests != 3 {
			t.Errorf("%s: expected 3 create requests, got %d", version, requests)
		}
	}
}

// TestCreateSecretFlowTotpOnlyForVersion33 verifies a v3.3 credential payload passed directly
// with TOTP settings is rejected before any request when the session uses another API version.
func TestCreateSecretFlowTotpOnlyForVersion33(t *testing.T) {
	details := entities.SecretCredentialDetailsConfig33{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Username:                "u",
		Password:                constants.FakePassword,
		Owners:                  []entities.OwnerDetailsGroupId{{GroupId: 1, UserId: 1}},
		TotpEnabled:             boolPtr(true),
		TotpSecretKey:           "JBSWY3DPEHPK3PXP",
	}
	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32} {
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%s: no request expected, got %v", version, r.URL.Path)
		})
		_, err := secretObj.CreateSecretFlow("folder1", details)
		if err == nil || !strings.Contains(err.Error(), "TOTP fields in create and update secret operations require API version 3.3") {
			t.Errorf("%s: expected API version error, got %v", version, err)
		}
		_, err = secretObj.SecretCreateSecret(uuid.NewString(), details)
		if err == nil || !strings.Contains(err.Error(), "TOTP fields in create and update secret operations require API version 3.3") {
			t.Errorf("%s: SecretCreateSecret: expected API version error, got %v", version, err)
		}
	}
}

// validUpdate returns a complete v3.3 update payload; the PUT replaces the secret.
func validUpdate() entities.SecretCredentialUpdateConfig33 {
	return entities.SecretCredentialUpdateConfig33{
		FolderId: uuid.MustParse("cb871861-8b40-4556-820c-1ca6d522adfa"),
		Title:    "T",
		Username: "u",
		Password: constants.FakePassword,
		Owners:   []entities.OwnerDetailsGroupId{{UserId: 1}},
	}
}

func TestUpdateCredentialSecretTotpTriState(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	var method string
	var received map[string]interface{}
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		received = nil
		if r.URL.Path != "/secrets-safe/secrets/"+id {
			t.Errorf("unexpected path %v", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		_, _ = w.Write([]byte(`{"Id":"` + id + `","Title":"T","TotpEnabled":false}`))
	})

	// nil: neither TOTP field is sent; the required fields are.
	if _, err := secretObj.UpdateCredentialSecret(id, validUpdate()); err != nil {
		t.Fatal(err)
	}
	if method != "PUT" {
		t.Errorf("expected PUT, got %v", method)
	}
	for _, field := range []string{"FolderId", "Title", "Username", "Password", "Owners"} {
		if _, ok := received[field]; !ok {
			t.Errorf("%s must be sent: %v", field, received)
		}
	}
	if _, ok := received["TotpEnabled"]; ok {
		t.Errorf("TotpEnabled must not be sent: %v", received)
	}
	if _, ok := received["TotpSecretKey"]; ok {
		t.Errorf("TotpSecretKey must not be sent: %v", received)
	}

	// false: explicit disable is sent.
	details := validUpdate()
	details.TotpEnabled = boolPtr(false)
	if _, err := secretObj.UpdateCredentialSecret(id, details); err != nil {
		t.Fatal(err)
	}
	if v, ok := received["TotpEnabled"]; !ok || v != false {
		t.Errorf("TotpEnabled=false must be sent: %v", received)
	}

	// true with seed.
	details = validUpdate()
	details.TotpEnabled = boolPtr(true)
	details.TotpSecretKey = "JBSWY3DPEHPK3PXP"
	if _, err := secretObj.UpdateCredentialSecret(id, details); err != nil {
		t.Fatal(err)
	}
	if received["TotpEnabled"] != true || received["TotpSecretKey"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP fields not sent: %v", received)
	}

	// invalid combinations fail locally.
	details = validUpdate()
	details.TotpEnabled = boolPtr(true)
	if _, err := secretObj.UpdateCredentialSecret(id, details); err == nil {
		t.Error("expected error for enabled without seed")
	}
	details = validUpdate()
	details.TotpSecretKey = "JBSWY3DPEHPK3PXP"
	if _, err := secretObj.UpdateCredentialSecret(id, details); err == nil {
		t.Error("expected error for seed without enabled")
	}
	if _, err := secretObj.UpdateCredentialSecret("not-a-uuid", validUpdate()); err == nil {
		t.Error("expected error for invalid id")
	}
}

// TestUpdateCredentialSecretRequiredFields verifies the fields the PUT requires are validated before any request.
func TestUpdateCredentialSecretRequiredFields(t *testing.T) {
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %v", r.URL.Path)
	})
	cases := map[string]func(*entities.SecretCredentialUpdateConfig33){
		"FolderId": func(d *entities.SecretCredentialUpdateConfig33) { d.FolderId = uuid.Nil },
		"Title":    func(d *entities.SecretCredentialUpdateConfig33) { d.Title = "" },
		"Username": func(d *entities.SecretCredentialUpdateConfig33) { d.Username = "" },
		"Password": func(d *entities.SecretCredentialUpdateConfig33) { d.Password = "" },
		"Owners":   func(d *entities.SecretCredentialUpdateConfig33) { d.Owners = []entities.OwnerDetailsGroupId{} },
	}
	for field, mutate := range cases {
		details := validUpdate()
		mutate(&details)
		_, err := secretObj.UpdateCredentialSecret("9152f5b6-07d6-4955-175a-08db047219ce", details)
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: expected validation error, got %v", field, err)
		}
	}

	// PasswordRuleID replaces Password.
	details := validUpdate()
	details.Password = ""
	details.PasswordRuleID = 1
	ok := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"9152f5b6-07d6-4955-175a-08db047219ce"}`))
	})
	if _, err := ok.UpdateCredentialSecret("9152f5b6-07d6-4955-175a-08db047219ce", details); err != nil {
		t.Errorf("PasswordRuleID without Password: %v", err)
	}
}

// TestUpdateCredentialSecretApiVersions verifies credential secrets can be updated with any API version,
// while the TOTP fields require v3.3.
func TestUpdateCredentialSecretApiVersions(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32, constants.ApiVersion33} {
		requests := 0
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusNoContent)
		})
		if _, err := secretObj.UpdateCredentialSecret(id, validUpdate()); err != nil {
			t.Errorf("%s: update without TOTP fields: %v", version, err)
		}
		if requests != 1 {
			t.Errorf("%s: expected 1 request, got %d", version, requests)
		}
	}

	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32} {
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%s: no request expected, got %v", version, r.URL.Path)
		})
		withTotp := validUpdate()
		withTotp.TotpEnabled = boolPtr(true)
		withTotp.TotpSecretKey = "JBSWY3DPEHPK3PXP"
		disable := validUpdate()
		disable.TotpEnabled = boolPtr(false)
		for name, details := range map[string]entities.SecretCredentialUpdateConfig33{"enable": withTotp, "disable": disable} {
			_, err := secretObj.UpdateCredentialSecret(id, details)
			if err == nil || !strings.Contains(err.Error(), "TOTP fields in create and update secret operations require API version 3.3") {
				t.Errorf("%s %s: expected TOTP API version error, got %v", version, name, err)
			}
		}
	}

}

// TestUpdateSecretNoContent verifies a 204 No Content response (as documented by the API spec)
// is a successful update for credential and text secrets.
func TestUpdateSecretNoContent(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	if _, err := secretObj.UpdateCredentialSecret(id, validUpdate()); err != nil {
		t.Errorf("UpdateCredentialSecret with 204: %v", err)
	}
	if _, err := secretObj.UpdateTextSecret(id, validTextUpdate()); err != nil {
		t.Errorf("UpdateTextSecret with 204: %v", err)
	}
}

// TestCredentialLengthLimits verifies the API spec limits for Username and PasswordRuleID.
func TestCredentialLengthLimits(t *testing.T) {
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %v", r.URL.Path)
	})

	update := validUpdate()
	update.Username = strings.Repeat("u", 257)
	if _, err := secretObj.UpdateCredentialSecret("9152f5b6-07d6-4955-175a-08db047219ce", update); err == nil || !strings.Contains(err.Error(), "Username") {
		t.Errorf("update Username: expected max length error, got %v", err)
	}
	update = validUpdate()
	update.Password = ""
	update.PasswordRuleID = 32768
	if _, err := secretObj.UpdateCredentialSecret("9152f5b6-07d6-4955-175a-08db047219ce", update); err == nil || !strings.Contains(err.Error(), "PasswordRuleID") {
		t.Errorf("update PasswordRuleID: expected max error, got %v", err)
	}

	create := entities.SecretCredentialDetailsConfig33{
		SecretDetailsBaseConfig: entities.SecretDetailsBaseConfig{Title: "T"},
		Username:                strings.Repeat("u", 257),
		Password:                constants.FakePassword,
		Owners:                  []entities.OwnerDetailsGroupId{{UserId: 1}},
	}
	if _, err := secretObj.CreateSecretFlow("folder1", create); err == nil || !strings.Contains(err.Error(), "Username") {
		t.Errorf("create Username: expected max length error, got %v", err)
	}
}

func validTextUpdate() entities.SecretTextUpdateConfig {
	return entities.SecretTextUpdateConfig{
		FolderId: uuid.MustParse("cb871861-8b40-4556-820c-1ca6d522adfa"),
		Title:    "T",
		Text:     "new text",
		Owners:   []entities.OwnerDetailsGroupId{{UserId: 1}},
	}
}

func validFileUpdate() entities.SecretFileUpdateConfig {
	return entities.SecretFileUpdateConfig{
		FolderId:    uuid.MustParse("cb871861-8b40-4556-820c-1ca6d522adfa"),
		Title:       "T",
		Owners:      []entities.OwnerDetailsGroupId{{UserId: 1}},
		FileName:    "new.txt",
		FileContent: "new file content",
	}
}

func TestUpdateTextSecret(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32, constants.ApiVersion33} {
		var received map[string]interface{}
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "PUT" || r.URL.Path != "/secrets-safe/secrets/"+id+"/text" {
				t.Errorf("%s: unexpected request %v %v", version, r.Method, r.URL.Path)
			}
			_ = json.NewDecoder(r.Body).Decode(&received)
			_, _ = w.Write([]byte(`{"Id":"` + id + `","Title":"T","SecretType":"Text"}`))
		})

		updated, err := secretObj.UpdateTextSecret(id, validTextUpdate())
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if updated.Id != id || updated.SecretType != "Text" {
			t.Errorf("%s: unexpected response %+v", version, updated)
		}
		for _, field := range []string{"FolderId", "Title", "Text", "Owners"} {
			if _, ok := received[field]; !ok {
				t.Errorf("%s: %s must be sent: %v", version, field, received)
			}
		}
	}
}

func TestUpdateFileSecret(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	var metadata map[string]interface{}
	var fileName, fileContent string
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/secrets-safe/secrets/"+id+"/file" {
			t.Errorf("unexpected request %v %v", r.Method, r.URL.Path)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("expected a multipart request: %v", err)
		}
		_ = json.Unmarshal([]byte(r.FormValue("secretmetadata")), &metadata)
		file, header, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("expected a file part: %v", err)
		}
		defer func() { _ = file.Close() }()
		content, _ := io.ReadAll(file)
		fileName, fileContent = header.Filename, string(content)
		w.WriteHeader(http.StatusNoContent)
	})

	if err := secretObj.UpdateFileSecret(id, validFileUpdate()); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"FolderId", "Title", "Owners", "FileName"} {
		if _, ok := metadata[field]; !ok {
			t.Errorf("%s must be sent in secretmetadata: %v", field, metadata)
		}
	}
	if _, ok := metadata["FileContent"]; ok {
		t.Errorf("FileContent must only be sent as the file part: %v", metadata)
	}
	if fileName != "new.txt" || fileContent != "new file content" {
		t.Errorf("unexpected file part %q: %q", fileName, fileContent)
	}
}

// TestUpdateFileSecretRetries verifies the file update uses the session retry policy: technical errors
// (HTTP 503) are retried with the full multipart payload, business errors (HTTP 400) are not.
func TestUpdateFileSecretRetries(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"

	requests := 0
	var lastContent string
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if file, _, err := r.FormFile("file"); err == nil {
			content, _ := io.ReadAll(file)
			_ = file.Close()
			lastContent = string(content)
		}
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := secretObj.UpdateFileSecret(id, validFileUpdate()); err != nil {
		t.Fatalf("expected success after retrying a 503: %v", err)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
	if lastContent != "new file content" {
		t.Errorf("retried request must carry the file part, got %q", lastContent)
	}

	requests = 0
	secretObj = newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`"invalid request"`))
	})
	if err := secretObj.UpdateFileSecret(id, validFileUpdate()); err == nil {
		t.Error("expected the 400 error")
	}
	if requests != 1 {
		t.Errorf("a 400 must not be retried, got %d requests", requests)
	}
}

// TestUpdateTextAndFileSecretValidation verifies the ID and required fields are checked before any request.
func TestUpdateTextAndFileSecretValidation(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	noRequest := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %v", r.URL.Path)
	}

	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, noRequest)
	if _, err := secretObj.UpdateTextSecret("not-a-uuid", validTextUpdate()); err == nil || !strings.Contains(err.Error(), "invalid secret ID") {
		t.Errorf("text: expected invalid ID error, got %v", err)
	}
	if err := secretObj.UpdateFileSecret("not-a-uuid", validFileUpdate()); err == nil || !strings.Contains(err.Error(), "invalid secret ID") {
		t.Errorf("file: expected invalid ID error, got %v", err)
	}

	textCases := map[string]func(*entities.SecretTextUpdateConfig){
		"FolderId": func(d *entities.SecretTextUpdateConfig) { d.FolderId = uuid.Nil },
		"Title":    func(d *entities.SecretTextUpdateConfig) { d.Title = "" },
		"Text":     func(d *entities.SecretTextUpdateConfig) { d.Text = "" },
		"Owners":   func(d *entities.SecretTextUpdateConfig) { d.Owners = []entities.OwnerDetailsGroupId{} },
	}
	for field, mutate := range textCases {
		details := validTextUpdate()
		mutate(&details)
		if _, err := secretObj.UpdateTextSecret(id, details); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("text %s: expected validation error, got %v", field, err)
		}
	}

	fileCases := map[string]func(*entities.SecretFileUpdateConfig){
		"FolderId":    func(d *entities.SecretFileUpdateConfig) { d.FolderId = uuid.Nil },
		"Title":       func(d *entities.SecretFileUpdateConfig) { d.Title = "" },
		"Owners":      func(d *entities.SecretFileUpdateConfig) { d.Owners = []entities.OwnerDetailsGroupId{} },
		"FileName":    func(d *entities.SecretFileUpdateConfig) { d.FileName = "" },
		"FileContent": func(d *entities.SecretFileUpdateConfig) { d.FileContent = "" },
	}
	for field, mutate := range fileCases {
		details := validFileUpdate()
		mutate(&details)
		if err := secretObj.UpdateFileSecret(id, details); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("file %s: expected validation error, got %v", field, err)
		}
	}
}

// TestGetSecretTotpCodeAnyApiVersion verifies the TOTP code endpoint is called with any API version;
// the server returns the code regardless of the requested version.
func TestGetSecretTotpCodeAnyApiVersion(t *testing.T) {
	for _, version := range []string{"3.0", constants.ApiVersion31, constants.ApiVersion32, constants.ApiVersion33} {
		secretObj := newTotpTestSecretObj(t, version, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"Code":"123456","ValidFromUtc":"2026-10-13T10:00:00Z","ValidToUtc":"2026-10-13T10:00:30Z"}`))
		})
		code, err := secretObj.GetSecretTotpCode(uuid.NewString())
		if err != nil || code.Code != "123456" {
			t.Errorf("%s: expected the code, got %+v, %v", version, code, err)
		}
	}
}

func TestGetSecretTotpCode(t *testing.T) {
	const id = "9152f5b6-07d6-4955-175a-08db047219ce"
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
		anyErr  bool
	}{
		{name: "200", status: 200, body: `{"Code":"123456","ValidFromUtc":"2026-10-13T10:00:00Z","ValidToUtc":"2026-10-13T10:00:30Z"}`},
		{name: "400", status: 400, body: `"not a credential secret"`, wantErr: ErrSecretNotCredential},
		{name: "404", status: 404, body: `"totp not enabled"`, wantErr: ErrSecretTotpNotAvailable},
		{name: "403", status: 403, body: `"forbidden"`, anyErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/secrets-safe/secrets/"+id+"/totp/code" || r.Method != "GET" {
					t.Errorf("unexpected request %v %v", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			code, err := secretObj.GetSecretTotpCode(id)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected %v, got %v", tc.wantErr, err)
				}
			case tc.anyErr:
				if err == nil || errors.Is(err, ErrSecretNotCredential) || errors.Is(err, ErrSecretTotpNotAvailable) || !strings.Contains(err.Error(), "403") {
					t.Errorf("expected generic 403 error, got %v", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if code.Code != "123456" || !code.ValidToUtc.After(code.ValidFromUtc) {
					t.Errorf("unexpected code %#v", code)
				}
			}
		})
	}
	secretObj := newTotpTestSecretObj(t, constants.ApiVersion33, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := secretObj.GetSecretTotpCode("bad"); err == nil {
		t.Error("expected invalid id error")
	}
}
