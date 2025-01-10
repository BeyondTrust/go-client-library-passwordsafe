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

func TestSignOut(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

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

	var authenticate, _ = Authenticate(*httpClientObj, backoffDefinition, testConfig.server.URL, "3.1", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)

	err := authenticate.SignOut()
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSignAppin(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "3.1", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = AuthenticateUsingApiKey(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "3.1", zapLogger, 300, "fake_api_key_")
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "3.1", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	var authenticate, _ = Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "3.1", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
