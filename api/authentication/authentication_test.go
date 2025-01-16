// Copyright 2024 BeyondTrust. All rights reserved.
// Package authentication implements functions to call Beyondtrust Secret Safe API.
// Unit tests for authentication package.
package authentication

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

type UserTestConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignApinResponse
}

type GetTokenConfig struct {
	name     string
	server   *httptest.Server
	response string
}

type GetPasswordSafeAuthenticationConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignApinResponse
}

// the recommended version is 3.1. If no version is specified,
// the default API version 3.0 will be used
var apiVersion string = "3.1"

var authParamsOauth *AuthenticationParametersObj
var authParamsKey *AuthenticationParametersObj
var zapLogger *logging.ZapLogger

func InitializeGlobalConfig() {

	logger, _ := zap.NewDevelopment()

	zapLogger = logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	// authentication using Oauth Method
	authParamsOauth = &AuthenticationParametersObj{
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

	// authentication using API Key
	authParamsKey = &AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                "https://fake.api.com:443/BeyondTrust/api/public/v3/",
		APIVersion:                 apiVersion,
		ClientID:                   "",
		ClientSecret:               "",
		ApiKey:                     "fakeone_a654+9sdf7+8we4f",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 300,
	}
}

func TestSignOut(t *testing.T) {

	InitializeGlobalConfig()

	testConfig := UserTestConfig{
		name: "TestSignOut",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(``))
			if err != nil {
				t.Error("Test case Failed")
			}

		})),
		response: nil,
	}

	var authenticate, _ = Authenticate(*authParamsOauth)
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	err := authenticate.SignOut()
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSignAppin(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)
	testConfig := UserTestConfig{
		name: "TestSignAppin",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "test@beyondtrust.com",
		},
	}

	response, err := authenticate.SignAppin(testConfig.server.URL+"/"+"TestSignAppin", "", "")

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSignAppinWithApiKey(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = AuthenticateUsingApiKey(*authParamsKey)
	testConfig := UserTestConfig{
		name: "TestSignAppinWithApiKey",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "test@beyondtrust.com",
		},
	}

	response, err := authenticate.SignAppin(testConfig.server.URL+"/"+"TestSignAppin", "", "fake_api_key_")

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestGetToken(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)
	testConfig := GetTokenConfig{
		name: "TestGetToken",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/connect/token":
				_, err := w.Write([]byte(`{"access_token": "fake_token", "expires_in": 600, "token_type": "Bearer", "scope": "publicapi"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_token",
	}

	response, err := authenticate.GetToken(testConfig.server.URL+"/"+"Auth/connect/token", "", "")

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestGetPasswordSafeAuthentication(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)
	testConfig := GetPasswordSafeAuthenticationConfig{
		name: "TestGetPasswordSafeAuthentication",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/connect/token":
				_, err := w.Write([]byte(`{"access_token": "fake_token", "expires_in": 600, "token_type": "Bearer", "scope": "publicapi"}`))
				if err != nil {
					t.Error("Test case Failed")
				}

			case "/Auth/SignAppIn":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"test@beyondtrust.com"}`))

				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "test@beyondtrust.com",
		},
	}
	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	response, err := authenticate.GetPasswordSafeAuthentication()

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}
