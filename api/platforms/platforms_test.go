// Copyright 2024 BeyondTrust. All rights reserved.
// Package platforms implements functions to managed platforms
// Unit tests for platforms package.
package platforms

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

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

func TestGetPlatformsListFlow(t *testing.T) {

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

		case "/Platforms":
			// 3 platforms
			_, err := w.Write([]byte(`[ { "PlatformID": 25, "Name": "Active Directory" }, { "PlatformID": 26, "Name": "AIX" }, { "PlatformID": 25, "Name": "Amazon" } ]`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	databaseObj, _ := NewPlatformObj(*authenticate, zapLogger)

	platformsList, err := databaseObj.GetPlatformsListFlow()

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if len(platformsList) != 3 {
		t.Errorf("Test case Failed %v, %v", len(platformsList), 3)
	}

}

func TestGetPlatformsListFlowEmptyList(t *testing.T) {

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

		case "/Platforms":
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
	databaseObj, _ := NewPlatformObj(*authenticate, zapLogger)

	_, err := databaseObj.GetPlatformsListFlow()

	expetedErrorMessage := "empty platforms list"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestGetPlatformsListFlowBadRequest(t *testing.T) {

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

		case "/Platforms":
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
	databaseObj, _ := NewPlatformObj(*authenticate, zapLogger)

	_, err := databaseObj.GetPlatformsListFlow()

	expetedErrorMessage := `error - status code: 400 - {"Bad Request"}`

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
}
