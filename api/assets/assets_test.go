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

func TestGetAssetsListByWorkgroupIdFlow(t *testing.T) {

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
			_, err := w.Write([]byte(`[{ "IPAddress": "192.168.1.1", "AssetName": "AssetNameByWorkGroupName", "DnsName": "server01.local" }]`))
			if err != nil {
				t.Error("Test case Failed")
			}

		case "/workgroups/1/assets":
			_, err := w.Write([]byte(`[{ "IPAddress": "192.168.1.1", "AssetName": "AssetNameByWorkGroupId", "DnsName": "server01.local" }]`))
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

	// get assets list by work group id.
	assetsList, err := workGroupObj.GetAssetsListByWorkgroupIdFlow("1")

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if len(assetsList) != 1 {
		t.Errorf("Test case Failed %v, %v", len(assetsList), 1)
	}

	// get assets list by work group name.
	assetsList, err = workGroupObj.GetAssetsListByWorkgroupNameFlow("workgroup_test")

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if len(assetsList) != 1 {
		t.Errorf("Test case Failed %v, %v", len(assetsList), 1)
	}

}

func TestGetAssetsListByWorkgroupIdFlowEmptyList(t *testing.T) {

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

		case "/workgroups/1/assets":
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
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	// get assets list by work group id.
	_, err := workGroupObj.GetAssetsListByWorkgroupIdFlow("1")

	expetedErrorMessage := "empty assets list"

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

// TestAssetsRejectDotSegmentIdentifiers ensures that callers cannot pass
// dot-segments (".", "..") or empty strings as path identifiers, because
// url.PathEscape does not encode "." and the resulting URL could be normalized
// into a different endpoint.
func TestAssetsRejectDotSegmentIdentifiers(t *testing.T) {
	InitializeGlobalConfig()

	authenticate, _ := authentication.Authenticate(*authParams)
	workGroupObj, _ := NewAssetObj(*authenticate, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.168.1.1",
		AssetName:       "asset_dot_segment",
		DnsName:         "host.local",
		DomainName:      "local",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Server",
		Description:     "Asset to exercise path-segment validation",
		OperatingSystem: "Ubuntu 22.04",
	}

	// CreateAssetByworkgroupIDFlow and CreateAssetByWorkGroupNameFlow already
	// reject empty strings; we exercise the dot-segment rejection (which is
	// enforced inside createAsset before any HTTP call).
	for _, bad := range []string{".", ".."} {
		if _, err := workGroupObj.CreateAssetByworkgroupIDFlow(bad, assetDetails); err == nil {
			t.Errorf("CreateAssetByworkgroupIDFlow(%q): expected validation error, got nil", bad)
		}
		if _, err := workGroupObj.CreateAssetByWorkGroupNameFlow(bad, assetDetails); err == nil {
			t.Errorf("CreateAssetByWorkGroupNameFlow(%q): expected validation error, got nil", bad)
		}
	}

	// GetAssetsListByWorkgroup{Id,Name}Flow must reject "", ".", and "..".
	for _, bad := range []string{"", ".", ".."} {
		if _, err := workGroupObj.GetAssetsListByWorkgroupIdFlow(bad); err == nil {
			t.Errorf("GetAssetsListByWorkgroupIdFlow(%q): expected validation error, got nil", bad)
		}
		if _, err := workGroupObj.GetAssetsListByWorkgroupNameFlow(bad); err == nil {
			t.Errorf("GetAssetsListByWorkgroupNameFlow(%q): expected validation error, got nil", bad)
		}
	}
}
