// Copyright 2025 BeyondTrust. All rights reserved.
// Package managed_systems implements functions to manage managed systems in Password Safe
// Unit tests for managed_systems package.
package managed_systems

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
	"github.com/google/uuid"
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

func TestCreateManagedSystemByAssetIdFlow(t *testing.T) {

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

		case "/Assets/1/ManagedSystems":
			_, err := w.Write([]byte(`{"ManagedSystemID": 13, "EntityTypeID": 1, "AssetID": 1}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByAssetIdDetailsConfig31{
		ManagedSystemsByAssetIdDetailsBaseConfig: entities.ManagedSystemsByAssetIdDetailsBaseConfig{
			PlatformID:                        1001,
			ContactEmail:                      "admin@example.com",
			Description:                       "Main Managed System",
			Port:                              8080,
			Timeout:                           30,
			SshKeyEnforcementMode:             1,
			PasswordRuleID:                    2,
			DSSKeyRuleID:                      5,
			LoginAccountID:                    10,
			ReleaseDuration:                   60,
			MaxReleaseDuration:                120,
			ISAReleaseDuration:                30,
			AutoManagementFlag:                true,
			FunctionalAccountID:               20,
			ElevationCommand:                  "sudo su",
			CheckPasswordFlag:                 true,
			ChangePasswordAfterAnyReleaseFlag: false,
			ResetPasswordOnMismatchFlag:       true,
			ChangeFrequencyType:               "first",
			ChangeFrequencyDays:               7,
			ChangeTime:                        "23:00",
		},
		RemoteClientType: "EPM",
	}

	response, err := managedSystemObj.CreateManagedSystemByAssetIdFlow("1", managedSystemDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response.ManagedSystemID != 13 {
		t.Errorf("Test case Failed %v, %v", response.ManagedSystemID, 13)
	}

}

func TestCreateManagedSystemByAssetIdFlowBadPayload(t *testing.T) {

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

		case "/Assets/1/ManagedSystems":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("Bad request required"))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByAssetIdDetailsConfig31{
		ManagedSystemsByAssetIdDetailsBaseConfig: entities.ManagedSystemsByAssetIdDetailsBaseConfig{
			PlatformID:   1001,
			ContactEmail: "admin@example.com",
			Description:  "Main Managed System",
			Port:         8080,
		},
		RemoteClientType: "EPM",
	}

	_, err := managedSystemObj.CreateManagedSystemByAssetIdFlow("1", managedSystemDetails)

	expetedErrorMessage := "Error in field ReleaseDuration : min / 1."

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestCreateManagedSystemByAssetIdFlowTechnicalError(t *testing.T) {

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

		case "/Assets/1/ManagedSystems":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("Bad Request"))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByAssetIdDetailsConfig31{
		ManagedSystemsByAssetIdDetailsBaseConfig: entities.ManagedSystemsByAssetIdDetailsBaseConfig{

			PlatformID:                        1001,
			ContactEmail:                      "admin@example.com",
			Description:                       "Main Managed System",
			Port:                              8080,
			Timeout:                           30,
			SshKeyEnforcementMode:             1,
			PasswordRuleID:                    2,
			DSSKeyRuleID:                      5,
			LoginAccountID:                    10,
			ReleaseDuration:                   60,
			MaxReleaseDuration:                120,
			ISAReleaseDuration:                30,
			AutoManagementFlag:                true,
			FunctionalAccountID:               20,
			ElevationCommand:                  "sudo su",
			CheckPasswordFlag:                 true,
			ChangePasswordAfterAnyReleaseFlag: false,
			ResetPasswordOnMismatchFlag:       true,
			ChangeFrequencyType:               "first",
			ChangeFrequencyDays:               7,
			ChangeTime:                        "23:00",
		},
		RemoteClientType: "EPM",
	}

	_, err := managedSystemObj.CreateManagedSystemByAssetIdFlow("1", managedSystemDetails)

	expetedErrorMessage := "error - status code: 400 - Bad Request"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestCreateManagedSystemByWorkGroupIdFlow(t *testing.T) {

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

		case "/Workgroups/1/ManagedSystems":
			_, err := w.Write([]byte(`{"ManagedSystemID": 15, "EntityTypeID": 1, "AssetID": 1}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByWorkGroupIdDetailsConfig30{
		ManagedSystemsByWorkGroupIdDetailsBaseConfig: entities.ManagedSystemsByWorkGroupIdDetailsBaseConfig{
			EntityTypeID:                       1,
			HostName:                           "example.com",
			IPAddress:                          "192.168.1.1",
			DnsName:                            "example.local",
			InstanceName:                       "Instance1",
			IsDefaultInstance:                  true,
			Template:                           "DefaultTemplate",
			ForestName:                         "exampleForest",
			UseSSL:                             false,
			PlatformID:                         2,
			NetBiosName:                        "EXAMPLE",
			ContactEmail:                       "admin@example.com",
			Description:                        "Example system",
			Port:                               443,
			Timeout:                            30,
			SshKeyEnforcementMode:              1,
			PasswordRuleID:                     0,
			DSSKeyRuleID:                       0,
			LoginAccountID:                     0,
			AccountNameFormat:                  1,
			OracleInternetDirectoryID:          uuid.New().String(),
			OracleInternetDirectoryServiceName: "OracleService",
			ReleaseDuration:                    60,
			MaxReleaseDuration:                 120,
			ISAReleaseDuration:                 180,
			AutoManagementFlag:                 false,
			FunctionalAccountID:                0,
			ElevationCommand:                   "sudo su",
			CheckPasswordFlag:                  true,
			ChangePasswordAfterAnyReleaseFlag:  true,
			ResetPasswordOnMismatchFlag:        false,
			ChangeFrequencyType:                "first",
			ChangeFrequencyDays:                7,
			ChangeTime:                         "02:00",
			AccessURL:                          "https://example.com",
		},
	}

	response, err := managedSystemObj.CreateManagedSystemByWorkGroupIdFlow("1", managedSystemDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response.ManagedSystemID != 15 {
		t.Errorf("Test case Failedd %v, %v", response.ManagedSystemID, 15)
	}

}

// workGroup Id is empty, please send a valid workGroup Id
func TestCreateManagedSystemByWorkGroupIdFlowEmptyWorkGroupId(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByDatabaseIdDetailsBaseConfig{}

	_, err := managedSystemObj.CreateManagedSystemByWorkGroupIdFlow("", managedSystemDetails)

	expetedErrorMessage := "workGroup Id is empty, please send a valid workGroup Id"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestCreateManagedSystemByDataBaseIdFlow(t *testing.T) {

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

		case "/Databases/1/ManagedSystems":
			_, err := w.Write([]byte(`{"ManagedSystemID": 15, "EntityTypeID": 1, "AssetID": 1}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByDatabaseIdDetailsBaseConfig{
		ContactEmail:                      "admin@example.com",
		Description:                       "Base config for managed system by DB ID",
		Timeout:                           30,
		PasswordRuleID:                    0,
		ReleaseDuration:                   120,
		MaxReleaseDuration:                525600,
		ISAReleaseDuration:                120,
		AutoManagementFlag:                true,
		FunctionalAccountID:               123,
		CheckPasswordFlag:                 true,
		ChangePasswordAfterAnyReleaseFlag: false,
		ResetPasswordOnMismatchFlag:       true,
		ChangeFrequencyType:               "xdays",
		ChangeFrequencyDays:               30,
		ChangeTime:                        "23:30",
	}

	response, err := managedSystemObj.CreateManagedSystemByDataBaseIdFlow("1", managedSystemDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response.ManagedSystemID != 15 {
		t.Errorf("Test case Failedd %v, %v", response.ManagedSystemID, 15)
	}

}

// Database Id is empty
func TestCreateManagedSystemByDataBaseIdFlowEmptyDatabaseId(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByDatabaseIdDetailsBaseConfig{}

	_, err := managedSystemObj.CreateManagedSystemByDataBaseIdFlow("", managedSystemDetails)

	expetedErrorMessage := "Database Id is empty, please send a valid Database Id"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

// Error in field Timeout : min / 1.
func TestCreateManagedSystemByDataBaseIdFlowBadData(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	managedSystemObj, _ := NewManagedSystem(*authenticate, zapLogger)

	managedSystemDetails := entities.ManagedSystemsByDatabaseIdDetailsBaseConfig{
		ContactEmail: "very_long_email_bad_email_bad_email@very_long_email_bad_email_bad_email.com",
	}

	_, err := managedSystemObj.CreateManagedSystemByDataBaseIdFlow("1", managedSystemDetails)

	expetedErrorMessage := "Error in field Timeout : min / 1."

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}
