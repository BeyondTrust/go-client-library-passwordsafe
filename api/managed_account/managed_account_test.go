// Copyright 2024 BeyondTrust. All rights reserved.
// Package managed_accounts implements functions to retrieve managed accounts
// Unit tests for managed_accounts package.
package managed_accounts

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

func TestManagedAccountGet(t *testing.T) {

	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)

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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlow",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlowFailedManagedAccounts",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestSecretGetSecret",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestSecretGetSecrets",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorCreatingRequest",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinesslErrorCreatingRequest",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorCredentialByRequestId",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinessErrorCredentialByRequestId",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowBusinessErrorAccountRequestCheckIn",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowTechnicalErrorAccountRequestCheckIn",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountFlowGetAccountTechnicalError",
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlowGetAccountBadResponse",
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
