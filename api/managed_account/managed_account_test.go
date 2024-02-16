// Copyright 2024 BeyondTrust. All rights reserved.
// Package managed_accounts implements functions to retrieve managed accounts
// Unit tests for managed_accounts package.
package managed_accounts

import (
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"log"
	"os"
	"strings"

	"net/http"
	"net/http/httptest"
	"testing"
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

var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
var logLogger = logging.NewLogLogger(logger)
var httpClient, _ = utils.GetHttpClient(5, true, "", "")
var authenticate, _ = authentication.Authenticate(httpClient, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", logLogger, 300)

func TestManagedAccountGet(t *testing.T) {

	testConfig := ManagedAccountTestConfig{
		name: "TestManagedAccountGet",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.Write([]byte(`{"SystemId": 1,"AccountId": 10}`))
		})),
		response: &entities.ManagedAccount{
			SystemId:  1,
			AccountId: 10,
		},
	}
	authenticate.ApiUrl = testConfig.server.URL + "/"
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)
	response, err := managedAccountObj.ManagedAccountGet("fake_system_name", "fake_account_name", testConfig.server.URL)

	if response != *testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, *testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountCreateRequest(t *testing.T) {

	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountCreateRequest",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.Write([]byte(`124`))
		})),
		response: "124",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)
	response, err := managedAccountObj.ManagedAccountCreateRequest(1, 10, testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestCredentialByRequestId(t *testing.T) {

	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestCredentialByRequestId",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.Write([]byte(`fake_credential`))
		})),
		response: "fake_credential",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)
	response, err := managedAccountObj.CredentialByRequestId("124", testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManagedAccountRequestCheckIn(t *testing.T) {

	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManagedAccountRequestCheckIn",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response
			w.Write([]byte(``))
		})),
		response: "",
	}

	authenticate.ApiUrl = testConfig.server.URL + "/"
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)
	response, err := managedAccountObj.ManagedAccountRequestCheckIn("124", testConfig.server.URL)

	if response != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManageAccountFlow(t *testing.T) {

	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlow",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

			case "/Auth/Signout":
				w.Write([]byte(``))

			case fmt.Sprintf("/ManagedAccounts"):
				w.Write([]byte(`{"SystemId":1,"AccountId":10}`))

			case "/Requests":
				w.Write([]byte(`124`))

			case "/Credentials/124":
				w.Write([]byte(`"fake_credential"`))

			case "/Requests/124/checkin":
				w.Write([]byte(``))

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_credential",
	}

	authenticate.ApiUrl = testConfig.server.URL
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)

	secretDictionary := make(map[string]string)
	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	response, err := managedAccountObj.ManageAccountFlow(managedAccounList, "/", secretDictionary)

	if response["oauthgrp_nocert/Test1"] != testConfig.response {
		t.Errorf("Test case Failed %v, %v", response, testConfig.response)
	}

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}
}

func TestManageAccountFlowNotFound(t *testing.T) {

	testConfig := ManagedAccountTestConfigStringResponse{
		name: "TestManageAccountFlowFailedManagedAccounts",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response accorging to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))

			case "/Auth/Signout":
				w.Write([]byte(``))

			case fmt.Sprintf("/ManagedAccounts"):
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`"Managed Account not found"`))

			case "/Requests":
				w.Write([]byte(`124`))

			case "/Credentials/124":
				w.Write([]byte(`"fake_credential"`))

			case "/Requests/124/checkin":
				w.Write([]byte(``))

			default:
				http.NotFound(w, r)
			}
		})),
		response: `got a non 200 status code: 404 - "Managed Account not found"`,
	}

	authenticate.ApiUrl = testConfig.server.URL
	managedAccountObj, _ := NewManagedAccountObj(*authenticate, logLogger)

	secretDictionary := make(map[string]string)
	managedAccounList := strings.Split("oauthgrp_nocert/Test1,oauthgrp_nocert/client_id", ",")

	_, err := managedAccountObj.ManageAccountFlow(managedAccounList, "/", secretDictionary)

	if err.Error() != testConfig.response {
		t.Errorf("Test case Failed %v, %v", err.Error(), testConfig.response)
	}
}
