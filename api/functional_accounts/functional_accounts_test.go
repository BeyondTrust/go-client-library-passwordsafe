// Copyright 2025 BeyondTrust. All rights reserved.
// Package functional_accounts implements functions to manage functional accounts in Password Safe
// Unit tests for functional_accounts package.
package functional_accounts

import (
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

var authParams *authentication.AuthenticationParametersObj
var zapLogger *logging.ZapLogger
var apiVersion string = constants.ApiVersion31

var functionalAccountDetails = entities.FunctionalAccountDetails{
	PlatformID:          1,
	DomainName:          "corp.example.com",
	AccountName:         "svc-monitoring",
	DisplayName:         "Monitoring Service Account7",
	Password:            constants.FakePassword,
	PrivateKey:          "private key content",
	Passphrase:          "my-passphrase",
	Description:         "Used for monitoring agents to access the platform",
	ElevationCommand:    "sudo",
	TenantID:            "123e4567-e89b-12d3-a456-426614174000",
	ObjectID:            "abc12345-def6-7890-gh12-ijklmnopqrst",
	Secret:              "secret-value",
	ServiceAccountEmail: "monitoring@project.iam.gserviceaccount.com",
	AzureInstance:       "AzurePublic",
}

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

func TestCreateFunctionalAccountsFlow(t *testing.T) {

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

		case "/FunctionalAccounts":
			_, err := w.Write([]byte(`{ "FunctionalAccountID": 13, "PlatformID": 1, "DomainName": "corp.example.com" }`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	functionalAccountObj, _ := NewFuncionalAccount(*authenticate, zapLogger)

	// successful case, happy path.
	functionalAccount, err := functionalAccountObj.CreateFunctionalAccountFlow(functionalAccountDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if functionalAccount.FunctionalAccountID != 13 {
		t.Errorf("Test case Failed %v, %v", functionalAccount.FunctionalAccountID, 13)
	}

	// error case, The field 'PlatformID' is required.
	functionalAccountDetails.PlatformID = 0
	functionalAccount, err = functionalAccountObj.CreateFunctionalAccountFlow(functionalAccountDetails)

	expetedErrorMessage := "The field 'PlatformID' is required."

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestCreateFunctionalAccountsFlowBadRequest(t *testing.T) {

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

		case "/FunctionalAccounts":
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
	functionalAccountObj, _ := NewFuncionalAccount(*authenticate, zapLogger)

	functionalAccountDetails.PlatformID = 1
	_, err := functionalAccountObj.CreateFunctionalAccountFlow(functionalAccountDetails)

	expetedErrorMessage := `error - status code: 400 - {"Bad Request"}`

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestGetFunctionalAccountsListFlow(t *testing.T) {

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

		case "/FunctionalAccounts":
			_, err := w.Write([]byte(`[ { "FunctionalAccountID": 1, "PlatformID": 4 }, { "FunctionalAccountID": 2, "PlatformID": 3 }, { "FunctionalAccountID": 3, "PlatformID": 47 }, { "FunctionalAccountID": 4, "PlatformID": 1 }, { "FunctionalAccountID": 5, "PlatformID": 1 }, { "FunctionalAccountID": 6, "PlatformID": 1 } ]`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	functionalAccountObj, _ := NewFuncionalAccount(*authenticate, zapLogger)

	functionalAccountsList, err := functionalAccountObj.GetFunctionalAccountsFlow()

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if len(functionalAccountsList) != 6 {
		t.Errorf("Test case Failed %v, %v", len(functionalAccountsList), 6)
	}

}

func TestDeleteFunctionalAccountById_Success(t *testing.T) {
	InitializeGlobalConfig()

	authenticate, err := authentication.Authenticate(*authParams)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && r.URL.Path == "/FunctionalAccounts/123":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	functionalAccountObj, _ := NewFuncionalAccount(*authenticate, zapLogger)

	err = functionalAccountObj.DeleteFunctionalAccountById(123)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestDeleteFunctionalAccountById_NotFound(t *testing.T) {
	InitializeGlobalConfig()

	authenticate, err := authentication.Authenticate(*authParams)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && r.URL.Path == "/FunctionalAccounts/999":
			w.WriteHeader(http.StatusNotFound)
			if _, err := w.Write([]byte(`{"error": "Functional account not found"}`)); err != nil {
				t.Errorf("Failed to write response: %v", err)
			}

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	functionalAccountObj, _ := NewFuncionalAccount(*authenticate, zapLogger)

	err = functionalAccountObj.DeleteFunctionalAccountById(999)

	if err == nil {
		t.Error("Expected an error for non-existent functional account, got nil")
	}

	// Verify error message contains relevant information
	errorMessage := err.Error()
	if !strings.Contains(errorMessage, "Functional account") && !strings.Contains(errorMessage, "functional account") {
		t.Errorf("Expected error message to contain 'functional account', got: %s", errorMessage)
	}
}
