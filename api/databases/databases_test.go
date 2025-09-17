// Copyright 2025 BeyondTrust. All rights reserved.
// Package databases implements functions to manage databases in Password Safe
// Unit tests for databases package.
package databases

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestCreateDatabaseFlow(t *testing.T) {

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

		case "/Assets/25/Databases":
			_, err := w.Write([]byte(`{ "DatabaseID": 7, "AssetID": 28, "PlatformID": 9, "InstanceName": "PrimaryDB", "IsDefaultInstance": false, "Port": 5432, "Version": "15.2", "Template": "StandardTemplate" }`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewDatabaseObj(*authenticate, zapLogger)

	databaseDetails := entities.DatabaseDetails{
		PlatformID:        9,
		InstanceName:      "PrimaryDB",
		IsDefaultInstance: true,
		Port:              5432,
		Version:           "15.2",
		Template:          "StandardTemplate",
	}

	response, err := databaseObj.CreateDatabaseFlow("25", databaseDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	expectedDataBaseId := 7
	expectedInstanceName := "PrimaryDB"

	if response.DatabaseID != expectedDataBaseId {
		t.Errorf("Test case Failed %v, %v", response.DatabaseID, expectedDataBaseId)
	}

	if response.InstanceName != expectedInstanceName {
		t.Errorf("Test case Failed %v, %v", response.DatabaseID, expectedInstanceName)
	}

}

func TestCreateDatabaseFlowBadRequest(t *testing.T) {

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

		case "/Assets/25/Databases":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("PlatformID is required"))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewDatabaseObj(*authenticate, zapLogger)

	databaseDetails := entities.DatabaseDetails{
		PlatformID:        9,
		InstanceName:      "PrimaryDB",
		IsDefaultInstance: true,
		Port:              5432,
		Version:           "15.2",
		Template:          "StandardTemplate",
	}

	_, err := databaseObj.CreateDatabaseFlow("25", databaseDetails)

	expetedErrorMessage := `error - status code: 400 - PlatformID is required`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestCreateDatabaseFlowTechnicalError(t *testing.T) {

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

		case "/Assets/25/Databases":
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(""))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewDatabaseObj(*authenticate, zapLogger)

	databaseDetails := entities.DatabaseDetails{
		PlatformID:        9,
		InstanceName:      "PrimaryDB",
		IsDefaultInstance: true,
		Port:              5432,
		Version:           "15.2",
		Template:          "StandardTemplate",
	}

	_, err := databaseObj.CreateDatabaseFlow("25", databaseDetails)

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}
