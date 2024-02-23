// Copyright 2024 BeyondTrust. All rights reserved.
// Package authentication implements functions to call Beyondtrust Secret Safe API.
// Unit tests for authentication package.
package authentication

import (
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"reflect"

	"net/http"
	"net/http/httptest"
	"testing"

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

	var authenticate, _ = Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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

	err := authenticate.SignOut(testConfig.server.URL)
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestSignAppin(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	var authenticate, _ = Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := UserTestConfig{
		name: "TestSignAppin",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
			if err != nil {
				t.Error("Test case Failed")
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "Felipe",
		},
	}

	response, err := authenticate.SignAppin(testConfig.server.URL+"/"+"TestSignAppin", "")

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

	var authenticate, _ = Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
	testConfig := GetTokenConfig{
		name: "TestGetToken",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
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

	var authenticate, _ = Authenticate(*httpClientObj, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
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
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

				if err != nil {
					t.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: &entities.SignApinResponse{
			UserId:       1,
			EmailAddress: "Felipe",
		},
	}
	authenticate.ApiUrl = testConfig.server.URL + "/"
	response, err := authenticate.GetPasswordSafeAuthentication()

	if !reflect.DeepEqual(response, *testConfig.response) {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}
