// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements functions to retrieve secrets
// Unit tests for secrets package.
package secrets

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
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
var apiVersion string = "3.1"

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
		EndpointURL:                "https://fake.api.com:443/BeyondTrust/api/public/v3/",
		APIVersion:                 apiVersion,
		ClientID:                   "fakeone_a654+9sdf7+8we4f",
		ClientSecret:               "fakeone_a654+9sdf7+8we4f",
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 30)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretTextDetails{
		Title:       "Secret Title",
		Description: "Title Description",
		Text:        "PasswordTest",
		OwnerType:   "User",
		OwnerId:     1,
		FolderId:    uuid.New(),
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretCredentialDetails{
		Title:       "Secret Title",
		Description: "Title Description",
		Username:    "TestUserName",
		Password:    "PasswordTest",
		OwnerType:   "User",
		OwnerId:     1,
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretFileDetails{
		Title:       "Secret Title",
		Description: "File Title Description",
		FileName:    "textfile.txt",
		FileContent: "Secret Content",
		OwnerType:   "User",
		OwnerId:     1,
		Owners: []entities.OwnerDetails{
			{
				OwnerId: 1,
				Owner:   "administrator",
				Email:   "test@beyondtrust.com",
			},
		},
	}

	response, err := secretObj.CreateSecretFlow("folder1", secretTextDetails)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	// exceeds the max file size value (5MB)
	n := 5_000_001
	fileContent := strings.Repeat("A", n)

	secretTextDetails := entities.SecretFileDetails{
		Title:       "Secret Title",
		Description: "File Title Description",
		FileName:    "textfile.txt",
		FileContent: fileContent,
		OwnerType:   "User",
		OwnerId:     1,
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretFileDetails{
		Title:       "Secret Title",
		Description: "File Title Description",
		FileName:    "textfile.txt",
		FileContent: "Secret Content",
		OwnerType:   "User",
		OwnerId:     1,
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretCredentialDetails{
		Title:       "",
		Description: "Title Description",
		Username:    "TestUserName",
		Password:    "PasswordTest",
		OwnerType:   "User",
		OwnerId:     1,
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretTextDetails{
		Title:       "Secret Title",
		Description: "Title Description",
		Text:        "PasswordTest",
		OwnerType:   "User",
		OwnerId:     1,
		FolderId:    uuid.New(),
		Owners: []entities.OwnerDetails{
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
		response: "empty Folder List",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

	secretTextDetails := entities.SecretTextDetails{
		Title:       "Secret Title",
		Description: "Title Description",
		Text:        "PasswordTest",
		OwnerType:   "User",
		OwnerId:     1,
		FolderId:    uuid.New(),
		Owners: []entities.OwnerDetails{
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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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

	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
	secretObj, _ := NewSecretObj(*authenticate, zapLogger, 4000)

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
