// Copyright 2025 BeyondTrust. All rights reserved.
// Package assets implements functions to manage assets in Password Safe
// Unit tests for assets package.
package assets

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
		ClientID:                   "",
		ClientSecret:               "",
		ApiKey:                     constants.FakeApiKey,
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 300,
	}
}

func TestCreateAssetFlow(t *testing.T) {

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

		case "/workgroups/workgroup_test/assets":
			_, err := w.Write([]byte(`{ "IPAddress": "192.168.1.1", "AssetName": "AssetNameByWorkGroupName", "DnsName": "server01.local" }`))
			if err != nil {
				t.Error("Test case Failed")
			}

		case "/workgroups/1/assets":
			_, err := w.Write([]byte(`{ "IPAddress": "192.168.1.1", "AssetName": "AssetNameByWorkGroupId", "DnsName": "server01.local" }`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.168.1.1",
		AssetName:       "WORKGROUP_" + uuid.New().String(),
		DnsName:         "server01.local",
		DomainName:      "local",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Server",
		Description:     "Primary application server",
		OperatingSystem: "Ubuntu 22.04",
	}

	// create asset by work group name.
	response, err := workGroupObj.CreateAssetByWorkGroupNameFlow("workgroup_test", assetDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response.AssetName != "AssetNameByWorkGroupName" {
		t.Errorf("Test case Failed %v, %v", response.AssetName, "AssetNameByWorkGroupName")
	}

	// create asset by work group id.
	response, err = workGroupObj.CreateAssetByworkgroupIDFlow("1", assetDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if response.AssetName != "AssetNameByWorkGroupId" {
		t.Errorf("Test case Failed %v, %v", response.AssetName, "AssetNameByWorkGroupId")
	}

}

func TestCreateAssetFlowEmptyWorkGroup(t *testing.T) {

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

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.168.1.1",
		AssetName:       "WORKGROUP_" + uuid.New().String(),
		DnsName:         "server01.local",
		DomainName:      "local",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Server",
		Description:     "Primary application server",
		OperatingSystem: "Ubuntu 22.04",
	}

	// trying to create an asset usging empty work group name
	_, err := workGroupObj.CreateAssetByWorkGroupNameFlow("", assetDetails)

	expetedErrorMessage := `workGroup name is empty, please send a valid workgroup name`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// trying to create an asset usging empty work group id
	_, err = workGroupObj.CreateAssetByworkgroupIDFlow("", assetDetails)

	expetedErrorMessage = `work groupId is empty, please send a valid workgroup id`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestCreateAssetFlowBadRequest(t *testing.T) {

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

		case "/workgroups/workgroup_test/assets":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{"An Asset by that name already exists"`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	apiUrl, _ := url.Parse(server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.168.1.1",
		AssetName:       "WORKGROUP_" + uuid.New().String(),
		DnsName:         "server01.local",
		DomainName:      "local",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Server",
		Description:     "Primary application server",
		OperatingSystem: "Ubuntu 22.04",
	}

	_, err := workGroupObj.CreateAssetByWorkGroupNameFlow("workgroup_test", assetDetails)

	expetedErrorMessage := `error - status code: 400 - {"An Asset by that name already exists"`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestCreateAssetFlowBadIPAddress(t *testing.T) {

	InitializeGlobalConfig()

	var authenticate, _ = authentication.Authenticate(*authParams)

	apiUrl, _ := url.Parse("https://127.0.0.1/")
	authenticate.ApiUrl = *apiUrl
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192",
		AssetName:       "WORKGROUP_" + uuid.New().String(),
		DnsName:         "server01.local",
		DomainName:      "local",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Server",
		Description:     "Primary application server",
		OperatingSystem: "Ubuntu 22.04",
	}

	_, err := workGroupObj.CreateAssetByWorkGroupNameFlow("workgroup_test", assetDetails)

	expetedErrorMessage := `Bad IP value: '192' in 'IPAddress' field`

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}
