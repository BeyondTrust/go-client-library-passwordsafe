// Copyright 2024 BeyondTrust. All rights reserved.
// Package authentication implements functions to call Beyondtrust Secret Safe API.
// Unit tests for authentication package.
package authentication

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

type UserTestConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignAppinResponse
}

type GetTokenConfig struct {
	name     string
	server   *httptest.Server
	response string
}

type GetPasswordSafeAuthenticationConfig struct {
	name     string
	server   *httptest.Server
	response *entities.SignAppinResponse
}

// the recommended version is 3.1. If no version is specified,
// the default API version 3.0 will be used
var apiVersion string = constants.ApiVersion31

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
		EndpointURL:                constants.FakeApiUrl,
		APIVersion:                 apiVersion,
		ClientID:                   constants.FakeClientId,
		ClientSecret:               constants.FakeClientSecret,
		ApiKey:                     "",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 300,
	}

	// authentication using API Key
	authParamsKey = &AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                constants.FakeApiUrl,
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
		response: &entities.SignAppinResponse{
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

func TestSignAppinWithWrongAPIURL(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)

	_, err := authenticate.SignAppin("https://fakeurl.com/BeyondTrust/"+"TestSignAppin", "", "")

	expectedResponse := `Post "https://fakeurl.com/BeyondTrust/TestSignAppin": dial tcp: lookup fakeurl.com`

	if !strings.Contains(err.Error(), expectedResponse) {
		t.Errorf("Test case Failed %v, %v", err.Error(), expectedResponse)
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
		response: &entities.SignAppinResponse{
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

func TestGetTokenDetails(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/connect/token":
			_, err := w.Write([]byte(`{"access_token": "fake_token", "expires_in": 600, "token_type": "Bearer", "scope": "publicapi"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	response, err := authenticate.GetTokenDetails(server.URL+"/Auth/connect/token", "", "")

	if err != nil {
		t.Fatalf("TestGetTokenDetails Failed: %v", err)
	}
	if response.AccessToken != "fake_token" {
		t.Errorf("AccessToken mismatch: got %q, want %q", response.AccessToken, "fake_token")
	}
	if response.ExpiresIn != 600 {
		t.Errorf("ExpiresIn mismatch: got %d, want 600", response.ExpiresIn)
	}
	if response.TokenType != "Bearer" {
		t.Errorf("TokenType mismatch: got %q, want %q", response.TokenType, "Bearer")
	}
	if response.Scope != "publicapi" {
		t.Errorf("Scope mismatch: got %q, want %q", response.Scope, "publicapi")
	}
}

func TestGetTokenDetails_ErrorResponse(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer server.Close()

	_, err := authenticate.GetTokenDetails(server.URL+"/Auth/connect/token", "", "")

	if err == nil {
		t.Fatal("TestGetTokenDetails_ErrorResponse: expected error on 401, got nil")
	}
}

func TestGetTokenDetails_InvalidJSON(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = Authenticate(*authParamsOauth)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	_, err := authenticate.GetTokenDetails(server.URL+"/Auth/connect/token", "", "")

	if err == nil {
		t.Fatal("TestGetTokenDetails_InvalidJSON: expected error for invalid JSON, got nil")
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
		response: &entities.SignAppinResponse{
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
