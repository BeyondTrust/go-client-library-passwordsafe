// Copyright 2026 BeyondTrust. All rights reserved.
// Package session provides a high-level facade for retrieving secrets
// using a pre-acquired access token (e.g. from a Kubernetes sidecar authenticator).
package session

import (
	"context"
	"fmt"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	managed_accounts "github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_account"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/secrets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	backoff "github.com/cenkalti/backoff/v4"
)

const (
	defaultMaxFileSecretSizeBytes = 5_000_000
	defaultAPIVersion             = "3.0"
)

// Parameters holds configuration for NewSessionFromToken.
// It intentionally omits ClientID, ClientSecret, and ApiKey.
type Parameters struct {
	HTTPClient                 utils.HttpClientObj
	BackoffDefinition          *backoff.ExponentialBackOff
	EndpointURL                string
	APIVersion                 string
	Logger                     logging.Logger
	RetryMaxElapsedTimeSeconds int
	MaxFileSecretSizeBytes     int
	DecryptSecrets             bool
}

// Session is a ready-to-use handle for retrieving secrets using a
// token supplied by an external authenticator such as the
// ps-integration-k8s-authenticator sidecar.
// Session is not goroutine-safe.
type Session struct {
	authObj   *authentication.AuthenticationObj
	secretObj *secrets.SecretObj
	maObj     *managed_accounts.ManagedAccountstObj
	log       logging.Logger
}

// validateSessionParams checks that the required fields in params are valid.
func validateSessionParams(accessToken string, params Parameters) error {
	switch {
	case accessToken == "":
		return fmt.Errorf("session: accessToken must not be empty")
	case params.EndpointURL == "":
		return fmt.Errorf("session: EndpointURL must not be empty")
	case params.Logger == nil:
		return fmt.Errorf("session: Logger must not be nil")
	case params.HTTPClient.HttpClient == nil:
		return fmt.Errorf("session: HTTPClient.HttpClient must not be nil")
	case params.MaxFileSecretSizeBytes < 0:
		return fmt.Errorf("session: MaxFileSecretSizeBytes must be greater than or equal to 0")
	}
	return nil
}

// resolveSessionDefaults fills in zero-value fields in params with sensible defaults.
func resolveSessionDefaults(params *Parameters) {
	if params.MaxFileSecretSizeBytes == 0 {
		params.MaxFileSecretSizeBytes = defaultMaxFileSecretSizeBytes
	}
	if params.APIVersion == "" {
		params.APIVersion = defaultAPIVersion
	}
	if params.BackoffDefinition == nil {
		params.BackoffDefinition = backoff.NewExponentialBackOff()
		if params.RetryMaxElapsedTimeSeconds > 0 {
			params.BackoffDefinition.MaxElapsedTime = time.Duration(params.RetryMaxElapsedTimeSeconds) * time.Second
		}
	}
}

// NewSessionFromToken creates a Session by signing in to BeyondTrust
// PasswordSafe using the provided access token. No OAuth credentials
// are required; the caller is responsible for supplying a valid,
// non-expired token.
func NewSessionFromToken(ctx context.Context, accessToken string, params Parameters) (*Session, error) {
	if err := validateSessionParams(accessToken, params); err != nil {
		return nil, err
	}

	resolveSessionDefaults(&params)

	httpClient := params.HTTPClient
	httpClient.Context = ctx

	authObj, err := authentication.Authenticate(authentication.AuthenticationParametersObj{
		HTTPClient:                 httpClient,
		BackoffDefinition:          params.BackoffDefinition,
		EndpointURL:                params.EndpointURL,
		APIVersion:                 params.APIVersion,
		ClientID:                   "",
		ClientSecret:               "",
		ApiKey:                     "",
		Logger:                     params.Logger,
		RetryMaxElapsedTimeSeconds: params.RetryMaxElapsedTimeSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("session: failed to build auth object: %w", err)
	}

	signInURL := authObj.ApiUrl.JoinPath("Auth/SignAppIn").String()
	_, err = authObj.SignAppin(signInURL, accessToken, "")
	if err != nil {
		return nil, fmt.Errorf("session: SignAppin failed: %w", err)
	}

	secretObj, err := secrets.NewSecretObj(*authObj, params.Logger, params.MaxFileSecretSizeBytes, params.DecryptSecrets)
	if err != nil {
		return nil, fmt.Errorf("session: failed to create SecretObj: %w", err)
	}

	maObj, err := managed_accounts.NewManagedAccountObj(*authObj, params.Logger)
	if err != nil {
		return nil, fmt.Errorf("session: failed to create ManagedAccountObj: %w", err)
	}

	return &Session{
		authObj:   authObj,
		secretObj: secretObj,
		maObj:     maObj,
		log:       params.Logger,
	}, nil
}

// GetSecret returns the secret value for a single Secrets Safe path.
func (s *Session) GetSecret(secretPath string, separator string) (string, error) {
	return s.secretObj.GetSecret(secretPath, separator)
}

// GetSecrets returns secret values for a list of Secrets Safe paths.
func (s *Session) GetSecrets(secretPaths []string, separator string) (map[string]string, error) {
	return s.secretObj.GetSecrets(secretPaths, separator)
}

// GetManagedAccount returns the password for a single managed account.
func (s *Session) GetManagedAccount(secretPath string, separator string) (string, error) {
	return s.maObj.GetSecret(secretPath, separator)
}

// GetManagedAccounts returns passwords for a list of managed accounts.
func (s *Session) GetManagedAccounts(secretPaths []string, separator string) (map[string]string, error) {
	return s.maObj.GetSecrets(secretPaths, separator)
}

// Close signs out of the BeyondTrust API session.
func (s *Session) Close() error {
	return s.authObj.SignOut()
}
