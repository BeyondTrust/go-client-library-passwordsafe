// Copyright 2024 BeyondTrust. All rights reserved.
// Package client implements functions to call Beyondtrust Secret Safe API.
package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	"net/url"

	backoff "github.com/cenkalti/backoff/v4"
)

// AuthenticationObj responsbile for authentication request data.
type AuthenticationObj struct {
	ApiUrl             url.URL
	ApiVersion         string
	clientId           string
	clientSecret       string
	apiKey             string
	HttpClient         utils.HttpClientObj
	ExponentialBackOff *backoff.ExponentialBackOff
	log                logging.Logger
}

type AuthenticationParametersObj struct {
	HTTPClient                 utils.HttpClientObj
	BackoffDefinition          *backoff.ExponentialBackOff
	EndpointURL                string
	APIVersion                 string
	ClientID                   string
	ClientSecret               string
	ApiKey                     string
	Logger                     logging.Logger
	RetryMaxElapsedTimeSeconds int
}

// Authenticate is responsible for Auth configuration using Client Id and Client secret.
// Prerequisites - use input validation methods before using this class.
func Authenticate(authenticationParametersObj AuthenticationParametersObj) (*AuthenticationObj, error) {

	apiUrl, err := url.Parse(authenticationParametersObj.EndpointURL)
	if err != nil {
		return nil, err
	}

	authenticationObj := &AuthenticationObj{
		ApiUrl:             *apiUrl,
		ApiVersion:         authenticationParametersObj.APIVersion,
		HttpClient:         authenticationParametersObj.HTTPClient,
		clientId:           authenticationParametersObj.ClientID,
		clientSecret:       authenticationParametersObj.ClientSecret,
		apiKey:             "",
		ExponentialBackOff: authenticationParametersObj.BackoffDefinition,
		log:                authenticationParametersObj.Logger,
	}

	authenticationObj.log.Debug("Signing in using Oauth")
	return authenticationObj, nil
}

// AuthenticateUsingApiKey is responsible for Auth configuration using API Key.
// Prerequisites - use input validation methods before using this class.
func AuthenticateUsingApiKey(authenticationParametersObj AuthenticationParametersObj) (*AuthenticationObj, error) {

	apiUrl, err := url.Parse(authenticationParametersObj.EndpointURL)
	if err != nil {
		return nil, err
	}
	authenticationObj := &AuthenticationObj{
		ApiUrl:             *apiUrl,
		ApiVersion:         authenticationParametersObj.APIVersion,
		HttpClient:         authenticationParametersObj.HTTPClient,
		clientId:           "",
		clientSecret:       "",
		apiKey:             authenticationParametersObj.ApiKey,
		ExponentialBackOff: authenticationParametersObj.BackoffDefinition,
		log:                authenticationParametersObj.Logger,
	}
	authenticationObj.log.Debug("Signing in using API Key")
	return authenticationObj, nil
}

// GetPasswordSafeAuthentication is responsible for getting a token and signing in.
func (authenticationObj *AuthenticationObj) GetPasswordSafeAuthentication() (entities.SignAppinResponse, error) {
	var accessToken string
	var err error

	if authenticationObj.clientId != "" && authenticationObj.clientSecret != "" {
		accessToken, err = authenticationObj.GetToken(authenticationObj.ApiUrl.JoinPath("Auth/connect/token").String(), authenticationObj.clientId, authenticationObj.clientSecret)
		if err != nil {
			return entities.SignAppinResponse{}, err
		}
	}

	signApinResponse, err := authenticationObj.SignAppin(authenticationObj.ApiUrl.JoinPath("Auth/SignAppIn").String(), accessToken, authenticationObj.apiKey)
	if err != nil {
		return entities.SignAppinResponse{}, err
	}
	return signApinResponse, nil
}

// GetToken is responsible for getting a token from the PS API.
func (authenticationObj *AuthenticationObj) GetToken(endpointUrl string, clientId string, clientSecret string) (string, error) {
	data, err := authenticationObj.GetTokenDetails(endpointUrl, clientId, clientSecret)
	if err != nil {
		return "", err
	}
	return data.AccessToken, nil
}

// GetTokenDetails is responsible for getting a token from the PS API and returning
// the full token response including expiry information.
// Unlike GetToken, which returns only the access token string, this method returns
// the complete entities.GetTokenResponse so callers can use expires_in to calculate
// exact token expiry without relying on a hard-coded default lifetime.
func (authenticationObj *AuthenticationObj) GetTokenDetails(endpointUrl string, clientId string, clientSecret string) (entities.GetTokenResponse, error) {

	params := url.Values{}
	params.Add("client_id", clientId)
	params.Add("client_secret", clientSecret)
	params.Add("grant_type", "client_credentials")

	var body io.ReadCloser
	var technicalError error
	var businessError error

	var buffer bytes.Buffer
	buffer.WriteString(params.Encode())

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         endpointUrl,
		HttpMethod:  "POST",
		Body:        buffer,
		Method:      constants.GetToken,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/x-www-form-urlencoded",
		ApiVersion:  "",
	}

	messageLog := fmt.Sprintf("%v %v", "POST", endpointUrl)
	authenticationObj.log.Debug(messageLog)

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.GetTokenResponse{}, technicalError
	}

	if businessError != nil {
		return entities.GetTokenResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return entities.GetTokenResponse{}, err
	}

	var data entities.GetTokenResponse
	if err = json.Unmarshal(bodyBytes, &data); err != nil {
		authenticationObj.log.Error(err.Error())
		return entities.GetTokenResponse{}, err
	}

	authenticationObj.log.Debug("Successfully retrieved token details")

	return data, nil

}

// SignAppin is responsible for creating a PS API session.
func (authenticationObj *AuthenticationObj) SignAppin(endpointUrl string, accessToken string, apiKey string) (entities.SignAppinResponse, error) {

	var userObject entities.SignAppinResponse
	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         endpointUrl,
		HttpMethod:  "POST",
		Body:        bytes.Buffer{},
		Method:      constants.SignAppin,
		AccessToken: accessToken,
		ApiKey:      apiKey,
		ContentType: "application/json",
		ApiVersion:  "",
	}

	messageLog := fmt.Sprintf("%v %v", "POST", endpointUrl)
	authenticationObj.log.Debug(messageLog)

	err := backoff.Retry(func() error {
		body, scode, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		if scode == 0 {
			return nil
		}
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if err != nil {
		return entities.SignAppinResponse{}, err
	}

	if scode == 0 {
		return entities.SignAppinResponse{}, technicalError
	}

	if businessError != nil {
		return entities.SignAppinResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return entities.SignAppinResponse{}, err
	}

	err = json.Unmarshal(bodyBytes, &userObject)

	if err != nil {
		authenticationObj.log.Error(err.Error())
		return entities.SignAppinResponse{}, err
	}
	authenticationObj.log.Info("Successfully Signed App In")
	return userObject, nil
}

// SignOut is responsible for closing the PS API session and cleaning up idle connections.
// Warn: should only be called one time for all data sources. The session is closed server
// side automatically after 20 minutes of uninterupted inactivity.
func (authenticationObj *AuthenticationObj) SignOut() error {

	var technicalError error
	var businessError error
	var body io.ReadCloser

	signOutUrl := authenticationObj.ApiUrl.JoinPath("Auth/Signout").String()

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         signOutUrl,
		HttpMethod:  "POST",
		Body:        bytes.Buffer{},
		Method:      constants.SignOut,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	messageLog := fmt.Sprintf("%v %v", "POST", signOutUrl)
	authenticationObj.log.Debug(messageLog)

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if businessError != nil {
		authenticationObj.log.Error(businessError.Error())
		return businessError
	}

	if body != nil {
		defer func() { _ = body.Close() }()
	}

	defer authenticationObj.HttpClient.HttpClient.CloseIdleConnections()
	authenticationObj.log.Info("Successfully Signed out.")
	return nil
}
