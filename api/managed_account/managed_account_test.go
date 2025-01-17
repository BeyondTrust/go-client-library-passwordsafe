// Copyright 2024 BeyondTrust. All rights reserved.
// Package managed_accounts implements functions to retrieve managed accounts
// Unit tests for managed_accounts package.
package managed_accounts

import (
	"fmt"
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

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

type ManagedAccountTestConfig struct {
	name     string
	server   *httptest.Server
	response *entities.ManagedAccount
}

type ManagedAccountTestConfigStringResponse struct {
	name     string
	server   *httptest.Server
	response string
}

type CreateManagedAccountsResponse struct {
	name     string
	server   *httptest.Server
	response *entities.CreateManagedAccountsResponse
}

// the recommended version is 3.1. If no version is specified,
// the default API version 3.0 will be used
var apiVersion string = "3.1"

<<<<<<< HEAD
func TestManagedAccountGet(t *testing.T) {
=======
var authParams *authentication.AuthenticationParametersObj
var zapLogger *logging.ZapLogger

func InitializeGlobalConfig() {
>>>>>>> main

	logger, _ := zap.NewDevelopment()

	zapLogger = logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

<<<<<<< HEAD
	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
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

func TestManagedAccountGet(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main

	testConfig := ManagedAccountTestConfig{
		name: "TestManagedAccountGet",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`{"SystemId": 1,"AccountId": 10}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		})),
		response: &entities.ManagedAccount{
			SystemId:  1,
			AccountId: 10,
		},
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	response, err := managedAccountObj.ManagedAccountGet("fake_system_name", "fake_account_name", testConfig.server.URL)

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountCreateRequest(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountCreateRequest",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`124`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "124",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	response, err := managedAccountObj.ManagedAccountCreateRequest(1, 10, testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestCredentialByRequestId(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestCredentialByRequestId",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(`fake_credential`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "fake_credential",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	response, err := managedAccountObj.CredentialByRequestId("124", testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountRequestCheckIn(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountRequestCheckIn",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			_, err := w.Write([]byte(``))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	response, err := managedAccountObj.ManagedAccountRequestCheckIn("124", testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManageAccountFlow(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlow",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_credential",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, err := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if response["oauthgrp_nocert/Test1"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManageAccountFlowNotFound(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlowNotFound",
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

			case "/ManagedAccounts":
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write([]byte(`"Managed Account not found"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))

				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))

				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))

				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	secrets, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(secrets) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestSecretGetSecret(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestSecretGetSecret",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_credential",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	response, err := managedAccountObj.GetSecret("oauthgrp_nocert/Test1", "/")

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSecretGetSecrets(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestSecretGetSecrets",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_credential",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	secretPaths := []string{"fake/Client", "fake/test_file_1"}
	response, err := managedAccountObj.GetSecrets(secretPaths, "/")

	if response["fake/Client"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountFlowTechnicalErrorCreatingRequest(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorCreatingRequest",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowBusinesslErrorCreatingRequest(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinesslErrorCreatingRequest",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowTechnicalErrorCredentialByRequestId(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorCredentialByRequestId",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowBusinessErrorCredentialByRequestId(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinessErrorCredentialByRequestId",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowBusinessErrorAccountRequestCheckIn(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinessErrorAccountRequestCheckIn",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin/":
				w.WriteHeader(http.StatusCreated)
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowTechnicalErrorAccountRequestCheckIn(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorAccountRequestCheckIn",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				w.WriteHeader(http.StatusGatewayTimeout)
				_, err := w.Write([]byte(``))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(response) != 0 {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

}

func TestManagedAccountFlowGetAccountTechnicalError(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowGetAccountTechnicalError",
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

			case "/ManagedAccounts":
				w.WriteHeader(http.StatusGatewayTimeout)
				_, err := w.Write([]byte(`"Managed Account not found"`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	secrets, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(secrets) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestManageAccountFlowGetAccountBadResponse(t *testing.T) {

<<<<<<< HEAD
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlowGetAccountBadResponse",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`fjfj}}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "",
	}
	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	secrets, _ := managedAccountObj.ManageAccountFlow(managedAccounList, "/")

	if len(secrets) != 0 {
		t.Errorf("Test case Failed")
	}
}

func TestManagedAccountCreateManagedAccount(t *testing.T) {
<<<<<<< HEAD
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := CreateManagedAccountsResponse{
		name: "TestManagedAccountCreateManagedAccount",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/ManagedSystems/5/ManagedAccounts":
				_, err := w.Write([]byte(`{"ManagedSystemID":5, "ManagedAccountID":10, "AccountName": "Managed Account Name"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: &entities.CreateManagedAccountsResponse{
			ManagedAccountID: 10,
			ManagedSystemID:  5,
			AccountName:      "Managed Account Name",
		},
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	accountAccountDetailsObj := entities.AccountDetails{
		AccountName:         "Managed_account_name",
		Password:            "MyPassword1707*!",
		Description:         "Sample account for testing",
		MaxReleaseDuration:  300000,
		ReleaseDuration:     300000,
		ISAReleaseDuration:  180,
		ChangeFrequencyDays: 1,
	}

	ManagedAccountCreateManagedAccountUrl := authenticate.ApiUrl.JoinPath("ManagedSystems", fmt.Sprintf("%d", 5), "ManagedAccounts").String()

	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	response, err := managedAccountObj.ManagedAccountCreateManagedAccount(accountAccountDetailsObj, ManagedAccountCreateManagedAccountUrl)

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountCreateManagedAccountExistingOne(t *testing.T) {
<<<<<<< HEAD
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountCreateManagedAccountExistingOne",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/ManagedSystems/5/ManagedAccounts":
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(`Managed System/Account already exists: 1/ManagedAccount10`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "error - status code: 400 - Managed System/Account already exists: 1/ManagedAccount10",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	ManagedAccountCreateManagedAccountUrl := authenticate.ApiUrl.JoinPath("ManagedSystems", fmt.Sprintf("%d", 5), "ManagedAccounts").String()

	accountAccountDetailsObj := entities.AccountDetails{
		AccountName: "Managed_account_name",
		Password:    "MyPassword1707*!",
		Description: "Sample account for testing",
	}

	_, err := managedAccountObj.ManagedAccountCreateManagedAccount(accountAccountDetailsObj, ManagedAccountCreateManagedAccountUrl)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v} %v", err.Error(), testConfig.response)
	}

}

func TestManagedAccountCreateManagedAccountFlow(t *testing.T) {
<<<<<<< HEAD
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := CreateManagedAccountsResponse{
		name: "TestManagedAccountCreateManagedAccountFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/ManagedSystems/5/ManagedAccounts":
				_, err := w.Write([]byte(`{"ManagedSystemID":5, "ManagedAccountID":10, "AccountName": "Managed_account_name"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/ManagedSystems":
				_, err := w.Write([]byte(`[{"ManagedSystemID":5, "SystemName":"system01", "EntityTypeID": 4}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: &entities.CreateManagedAccountsResponse{
			ManagedAccountID: 10,
			ManagedSystemID:  5,
			AccountName:      "Managed_account_name",
		},
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	accountAccountDetailsObj := entities.AccountDetails{
		AccountName:         "Managed_account_name",
		Password:            "MyPassword1707*!",
		Description:         "Sample account for testing",
		MaxReleaseDuration:  300000,
		ReleaseDuration:     300000,
		ISAReleaseDuration:  180,
		ChangeFrequencyDays: 1,
	}
	response, err := managedAccountObj.ManageAccountCreateFlow("system01", accountAccountDetailsObj)

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestManagedAccountCreateManagedAccountFlowSystemNotFound(t *testing.T) {
<<<<<<< HEAD
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountCreateManagedAccountFlowSystemNotFound",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/ManagedSystems/5/ManagedAccounts":
				_, err := w.Write([]byte(`{"ManagedSystemID":5, "ManagedAccountID":10, "AccountName": "Managed Account Name"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/ManagedSystems":
				_, err := w.Write([]byte(`[{"ManagedSystemID":5, "SystemName":"system01", "EntityTypeID": 4}]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "managed system system02 was not found in managed system list",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	accountAccountDetailsObj := entities.AccountDetails{
		AccountName:         "Managed_account_name",
		Password:            "MyPassword1707*!",
		Description:         "Sample account for testing",
		MaxReleaseDuration:  300000,
		ReleaseDuration:     300000,
		ISAReleaseDuration:  180,
		ChangeFrequencyDays: 1,
	}
	_, err := managedAccountObj.ManageAccountCreateFlow("system02", accountAccountDetailsObj)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}

}

func TestManagedAccountCreateManagedAccountFlowEmptySystemList(t *testing.T) {
<<<<<<< HEAD
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", apiVersion, "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======

	var authenticate, _ = authentication.Authenticate(*authParams)
>>>>>>> main
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountCreateManagedAccountFlowEmptySystemList",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {
			case "/ManagedSystems":
				_, err := w.Write([]byte(`[]`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "empty System Account List",
	}

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	accountAccountDetailsObj := entities.AccountDetails{
		AccountName:         "Managed_account_name",
		Password:            "MyPassword1707*!",
		Description:         "Sample account for testing",
		MaxReleaseDuration:  300000,
		ReleaseDuration:     300000,
		ISAReleaseDuration:  180,
		ChangeFrequencyDays: 1,
	}

	_, err := managedAccountObj.ManageAccountCreateFlow("system02", accountAccountDetailsObj)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v} %v", err.Error(), testConfig.response)
	}

}
