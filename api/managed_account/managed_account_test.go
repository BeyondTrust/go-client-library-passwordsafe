// Copyright 2025 BeyondTrust. All rights reserved.
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
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
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

func TestManagedAccountGet(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

// TestGetManagedAccountSecretSystemNameWithSeparator covers a system name that
// contains the path separator, which is rejected by the path validation
// GetSecret/ManageAccountFlow rely on (BIPS-37662).
func TestGetManagedAccountSecretSystemNameWithSeparator(t *testing.T) {

	InitializeGlobalConfig()

	systemNameWithSeparator := "Accounts - AD/EntraID"

	var gotSystemName, gotAccountName string

	var authenticate, _ = authentication.Authenticate(*authParams)
	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestGetManagedAccountSecretSystemNameWithSeparator",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error

			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err = w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))

			case "/Auth/Signout":
				_, err = w.Write([]byte(``))

			case "/ManagedAccounts":
				gotSystemName = r.URL.Query().Get("systemName")
				gotAccountName = r.URL.Query().Get("accountName")
				_, err = w.Write([]byte(`{"SystemId":1,"AccountId":10}`))

			case "/Requests":
				_, err = w.Write([]byte(`124`))

			case "/Credentials/124":
				_, err = w.Write([]byte(`fake_credential`))

			case "/Requests/124/checkin":
				_, err = w.Write([]byte(``))

			default:
				http.NotFound(w, r)
			}

			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: "fake_credential",
	}
	defer testConfig.server.Close()

	apiUrl, _ := url.Parse(testConfig.server.URL)
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	response, err := managedAccountObj.GetManagedAccountSecret(systemNameWithSeparator, "Test1")

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if gotSystemName != systemNameWithSeparator {
		t.Errorf("Test case Failed %v, %v", gotSystemName, systemNameWithSeparator)
	}

	if gotAccountName != "Test1" {
		t.Errorf("Test case Failed %v, %v", gotAccountName, "Test1")
	}
}

func TestGetManagedAccountSecretInvalidNames(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	// Empty system name, no API call is made.
	_, err := managedAccountObj.GetManagedAccountSecret("  ", "Test1")

	expectedErrorMessage := "invalid system name length=2, valid length between 1 and 128"

	if err == nil {
		t.Fatalf("Test case Failed, expected error %v", expectedErrorMessage)
	}

	if err.Error() != expectedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expectedErrorMessage)
	}

	// Empty account name, no API call is made.
	_, err = managedAccountObj.GetManagedAccountSecret("system01", "")

	expectedErrorMessage = "system name=system01 but found invalid account name length=0, valid length between 1 and 245"

	if err == nil {
		t.Fatalf("Test case Failed, expected error %v", expectedErrorMessage)
	}

	if err.Error() != expectedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expectedErrorMessage)
	}
}

func TestDecodeCredentialValue(t *testing.T) {

	testCases := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "quoted JSON string",
			raw:      `"fake_credential"`,
			expected: "fake_credential",
		},
		{
			name:     "raw body that is not JSON",
			raw:      `fake_credential`,
			expected: "fake_credential",
		},
		{
			name:     "literal null body falls back to the raw response",
			raw:      `null`,
			expected: "null",
		},
		{
			name:     "bare JSON number falls back to the raw response",
			raw:      `124`,
			expected: "124",
		},
		{
			name:     "JSON surrogate pair escape is decoded",
			raw:      `"\ud83d\ude00"`,
			expected: "\U0001F600",
		},
		{
			name:     "empty JSON string",
			raw:      `""`,
			expected: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response := decodeCredentialValue(testCase.raw)

			if response != testCase.expected {
				t.Errorf("Test case Failed %v, %v", response, testCase.expected)
			}
		})
	}
}

func TestManageAccountFlowNotFound(t *testing.T) {

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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
		Password:            constants.FakePassword,
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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
		Password:    constants.FakePassword,
		Description: "Sample account for testing",
	}

	_, err := managedAccountObj.ManagedAccountCreateManagedAccount(accountAccountDetailsObj, ManagedAccountCreateManagedAccountUrl)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v} %v", err.Error(), testConfig.response)
	}

}

func TestManagedAccountCreateManagedAccountFlow(t *testing.T) {

	var authenticate, _ = authentication.Authenticate(*authParams)
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
		Password:            constants.FakePassword,
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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
		Password:            constants.FakePassword,
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

	var authenticate, _ = authentication.Authenticate(*authParams)
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
		Password:            constants.FakePassword,
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

func TestGetManagedAccountsListFlow(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			// 2 ManagedAccounts
			_, err := w.Write([]byte(`[ { "PlatformID": 4, "SystemId": 1, "SystemName": "system01", "InstanceName": "", "DomainName": null, "AccountId": 24 }, { "PlatformID": 4, "SystemId": 2, "SystemName": "system02", "InstanceName": "", "DomainName": null, "AccountId": 24 } ]`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	managedAccountList, err := databaseObj.GetManagedAccountsListFlow()

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if len(managedAccountList) != 2 {
		t.Errorf("Test case Failed %v, %v", len(managedAccountList), 2)
	}

}

func TestGetManagedAccountsListFlowEmptyList(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			// empty list
			_, err := w.Write([]byte(`[]`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	_, err := databaseObj.GetManagedAccountsListFlow()

	expetedErrorMessage := "empty managed accounts list"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestGetManagedAccountsListFlowBadRequest(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			// bad request
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{"Bad Request"}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewManagedAccountObj(*authenticate, zapLogger)

	_, err := databaseObj.GetManagedAccountsListFlow()

	expetedErrorMessage := `error - status code: 400 - {"Bad Request"}`

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
}

func TestDeleteManagedAccountById_Success(t *testing.T) {
	InitializeGlobalConfig()
	var authenticate, _ = authentication.Authenticate(*authParams)
	// Mock server returns 200 OK for DELETE
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	err := managedAccountObj.DeleteManagedAccountById(123)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestDeleteManagedAccountById_NotFound(t *testing.T) {
	InitializeGlobalConfig()
	var authenticate, _ = authentication.Authenticate(*authParams)
	// Mock server returns 404 Not Found for DELETE
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	err := managedAccountObj.DeleteManagedAccountById(999)
	if err == nil {
		t.Errorf("Expected error for 404 response, got nil")
	}
}

func TestDeleteManagedAccountById_ServerError(t *testing.T) {
	InitializeGlobalConfig()
	var authenticate, _ = authentication.Authenticate(*authParams)
	// Mock server returns 500 Internal Server Error for DELETE
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, zapLogger)
	err := managedAccountObj.DeleteManagedAccountById(500)
	if err == nil {
		t.Errorf("Expected error for 500 response, got nil")
	}
}
