// Copyright 2026 BeyondTrust. All rights reserved.
package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

func testLogger(t *testing.T) logging.Logger {
	t.Helper()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	return logging.NewZapLogger(logger)
}

func testHTTPClient(t *testing.T, logger logging.Logger) utils.HttpClientObj {
	t.Helper()

	httpClientObj, err := utils.GetHttpClient(5, false, "", "", logger)
	if err != nil {
		t.Fatalf("failed to create http client: %v", err)
	}

	return *httpClientObj
}

func testBackoff() *backoff.ExponentialBackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = time.Second
	return b
}

func TestNewSessionFromToken_EmptyToken(t *testing.T) {
	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "", Parameters{
		EndpointURL:       "http://example.com",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "accessToken must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_EmptyEndpointURL(t *testing.T) {
	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "token", Parameters{
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "EndpointURL must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_NilLogger(t *testing.T) {
	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       "http://example.com",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            nil,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "Logger must not be nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_NilUnderlyingHTTPClient(t *testing.T) {
	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       "http://example.com",
		HTTPClient:        utils.HttpClientObj{},
		BackoffDefinition: testBackoff(),
		Logger:            logger,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "HTTPClient.HttpClient must not be nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_NegativeMaxFileSecretSizeBytes(t *testing.T) {
	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:            "http://example.com",
		HTTPClient:             testHTTPClient(t, logger),
		BackoffDefinition:      testBackoff(),
		Logger:                 logger,
		MaxFileSecretSizeBytes: -1,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "MaxFileSecretSizeBytes must be greater than or equal to 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_SignAppinFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	_, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "SignAppin failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSessionFromToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if sessionObj == nil {
		t.Fatal("expected non-nil session")
	}

	_ = sessionObj.Close()
}

func TestSession_GetSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		case "/secrets-safe/secrets":
			_, _ = w.Write([]byte(`[{"Password":"secret_value","Id":"id-1","Title":"title"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	secret, err := sessionObj.GetSecret("folder/title", "/")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if secret != "secret_value" {
		t.Fatalf("unexpected secret value: %v", secret)
	}
}

func TestSession_GetSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		case "/secrets-safe/secrets":
			title := r.URL.Query().Get("title")
			if title == "title1" {
				_, _ = w.Write([]byte(`[{"Password":"value1","Id":"id-1","Title":"title1"}]`))
				return
			}

			if title == "title2" {
				_, _ = w.Write([]byte(`[{"Password":"value2","Id":"id-2","Title":"title2"}]`))
				return
			}

			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	response, err := sessionObj.GetSecrets([]string{"folder/title1", "folder/title2"}, "/")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	expected := map[string]string{
		"folder/title1": "value1",
		"folder/title2": "value2",
	}

	if !reflect.DeepEqual(response, expected) {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestSession_GetManagedAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		case "/ManagedAccounts":
			_, _ = w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
		case "/Requests":
			_, _ = w.Write([]byte(`124`))
		case "/Credentials/124":
			_, _ = w.Write([]byte(`"managed_password"`))
		case "/Requests/124/checkin":
			_, _ = w.Write([]byte(``))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	secret, err := sessionObj.GetManagedAccount("system/account", "/")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if secret != "managed_password" {
		t.Fatalf("unexpected secret value: %v", secret)
	}
}

func TestSession_Close(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	err = sessionObj.Close()
	if err != nil {
		t.Fatalf("expected no error on close, got: %v", err)
	}
}

func TestNewSessionFromToken_DefaultMaxFileSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		case "/secrets-safe/secrets":
			_, _ = w.Write([]byte(`[{"SecretType":"FILE","Password":"","Id":"id-1","Title":"title"}]`))
		case "/secrets-safe/secrets/id-1/file/download":
			_, _ = w.Write([]byte(`file-secret`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:            server.URL + "/",
		HTTPClient:             testHTTPClient(t, logger),
		BackoffDefinition:      testBackoff(),
		Logger:                 logger,
		APIVersion:             "3.1",
		MaxFileSecretSizeBytes: 0,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	secret, err := sessionObj.GetSecret("folder/title", "/")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if secret != "file-secret" {
		t.Fatalf("unexpected secret value: %v", secret)
	}
}

func TestNewSessionFromToken_DefaultAPIVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	if sessionObj.authObj.ApiVersion != "3.0" {
		t.Fatalf("unexpected api version: %v", sessionObj.authObj.ApiVersion)
	}
}

func TestNewSessionFromToken_NilBackoffUsesDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		case "/Auth/Signout":
			_, _ = w.Write([]byte(``))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	sessionObj, err := NewSessionFromToken(context.Background(), "token", Parameters{
		EndpointURL:                server.URL + "/",
		HTTPClient:                 testHTTPClient(t, logger),
		BackoffDefinition:          nil,
		Logger:                     logger,
		APIVersion:                 "3.1",
		RetryMaxElapsedTimeSeconds: 1,
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	defer func() { _ = sessionObj.Close() }()

	if sessionObj.authObj.ExponentialBackOff == nil {
		t.Fatal("expected non-nil backoff definition")
	}
}

func TestNewSessionFromToken_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Auth/SignAppIn":
			time.Sleep(50 * time.Millisecond)
			_, _ = w.Write([]byte(`{"UserId":1,"EmailAddress":"test@beyondtrust.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	logger := testLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewSessionFromToken(ctx, "token", Parameters{
		EndpointURL:       server.URL + "/",
		HTTPClient:        testHTTPClient(t, logger),
		BackoffDefinition: testBackoff(),
		Logger:            logger,
		APIVersion:        "3.1",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
