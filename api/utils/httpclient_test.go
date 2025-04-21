package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

var body io.ReadCloser
var technicalError error
var businessError error

func TestCallSecretSafeAPI(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)

	params := url.Values{}
	params.Add("client_id", "test")
	params.Add("client_secret", "test")
	params.Add("grant_type", "client_credentials")

	var buffer bytes.Buffer
	buffer.WriteString(params.Encode())

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         server.URL + "/Auth/connect/token",
		HttpMethod:  "POST",
		Body:        buffer,
		Method:      constants.GetToken,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	body, _, technicalError, businessError = httpClientObj.CallSecretSafeAPI(*callSecretSafeAPIObj)

	if technicalError != nil {
		t.Errorf("Test case Failed: %v", technicalError)
	}

	if businessError != nil {
		t.Errorf("Test case Failed: %v", technicalError)
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		t.Errorf("Test case Failed: %v", technicalError)
	}

	responseString := string(bodyBytes)

	var data entities.GetTokenResponse

	err = json.Unmarshal([]byte(responseString), &data)
	if err != nil {
		t.Errorf("Test case Failed: %v", technicalError)
	}

}

func TestCallSecretSafeAPIError500(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mocking Response according to the endpoint path
		switch r.URL.Path {
		case "/Auth/connect/token":
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(``))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)

	params := url.Values{}
	params.Add("client_id", "test")
	params.Add("client_secret", "test")
	params.Add("grant_type", "client_credentials")

	var buffer bytes.Buffer
	buffer.WriteString(params.Encode())

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         server.URL + "/Auth/connect/token",
		HttpMethod:  "POST",
		Body:        buffer,
		Method:      constants.GetToken,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	// Technical error case - Error 500.
	_, _, technicalError, _ = httpClientObj.CallSecretSafeAPI(*callSecretSafeAPIObj)

	if technicalError == nil {
		t.Errorf("Test case Failed")
	}

}

func TestCallSecretSafeAPIError400(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mocking Response according to the endpoint path
		switch r.URL.Path {
		case "/Auth/connect/token":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(``))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)

	params := url.Values{}
	params.Add("client_id", "test")
	params.Add("client_secret", "test")
	params.Add("grant_type", "client_credentials")

	var buffer bytes.Buffer
	buffer.WriteString(params.Encode())

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         server.URL + "/Auth/connect/token",
		HttpMethod:  "POST",
		Body:        buffer,
		Method:      constants.GetToken,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	// Business error case - Error 400.
	_, _, _, businessError = httpClientObj.CallSecretSafeAPI(*callSecretSafeAPIObj)

	if businessError == nil {
		t.Errorf("Test case Failed")
	}

}

func TestCreateMultiPartRequest(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mocking Response according to the endpoint path
		switch r.URL.Path {
		case "/secrets/file":
			_, err := w.Write([]byte(`file created`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)
	_, err := httpClientObj.CreateMultiPartRequest(server.URL+"/secrets/file", "file_name.txt", []byte("metadata"), "file_content")

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestGetGeneralList(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	var tokenData entities.GetTokenResponse

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(30) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)
	bodyBytes, err := httpClientObj.GetGeneralList(server.URL+"/Auth/connect/token", constants.ApiVersion31, "GetToken", backoffDefinition)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	err = json.Unmarshal(bodyBytes, &tokenData)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	if tokenData.AccessToken != "fake_token" {
		t.Errorf("Test case Failed %v, %v", tokenData.AccessToken, "fake_token")
	}

}

func TestGetGeneralListBadRequest(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mocking Response according to the endpoint path
		switch r.URL.Path {
		case "/Auth/connect/token":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{"Bad Request"}`))
			if err != nil {
				t.Error("Test case Failed")
			}

		default:
			http.NotFound(w, r)
		}
	}))

	logger, _ := zap.NewDevelopment()
	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(30) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	httpClientObj, _ := GetHttpClient(30, false, "", "", zapLogger)
	_, err := httpClientObj.GetGeneralList(server.URL+"/Auth/connect/token", constants.ApiVersion31, "GetToken", backoffDefinition)

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}
