// Copyright 2024 BeyondTrust. All rights reserved.
// Package client implements functions to call Beyondtrust Secret Safe API.
package authentication

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	"net/url"

	backoff "github.com/cenkalti/backoff/v4"
)

// AuthenticationObj responsbile for authentication request data.
type AuthenticationObj struct {
	ApiUrl             url.URL
	clientId           string
	clientSecret       string
	apiKey             string
	HttpClient         utils.HttpClientObj
	ExponentialBackOff *backoff.ExponentialBackOff
	log                logging.Logger
}

// Authenticate is responsible for Auth configuration using Client Id and Client secret.
// Prerequisites - use input validation methods before using this class.
func Authenticate(httpClient utils.HttpClientObj, backoffDefinition *backoff.ExponentialBackOff, endpointUrl string, clientId string, clientSecret string, logger logging.Logger, retryMaxElapsedTimeSeconds int) (*AuthenticationObj, error) {

	apiUrl, _ := url.Parse(endpointUrl)
	authenticationObj := &AuthenticationObj{
		ApiUrl:             *apiUrl,
		HttpClient:         httpClient,
		clientId:           clientId,
		clientSecret:       clientSecret,
		apiKey:             "",
		ExponentialBackOff: backoffDefinition,
		log:                logger,
	}

	authenticationObj.log.Debug("Signing in using Oauth")
	return authenticationObj, nil
}

// AuthenticateUsingApiKey is responsible for Auth configuration using API Key.
// Prerequisites - use input validation methods before using this class.
func AuthenticateUsingApiKey(httpClient utils.HttpClientObj, backoffDefinition *backoff.ExponentialBackOff, endpointUrl string, logger logging.Logger, retryMaxElapsedTimeSeconds int, apiKey string) (*AuthenticationObj, error) {

	apiUrl, _ := url.Parse(endpointUrl)
	authenticationObj := &AuthenticationObj{
		ApiUrl:             *apiUrl,
		HttpClient:         httpClient,
		clientId:           "",
		clientSecret:       "",
		apiKey:             apiKey,
		ExponentialBackOff: backoffDefinition,
		log:                logger,
	}
	authenticationObj.log.Debug("Signing in using API Key")
	return authenticationObj, nil
}

// GetPasswordSafeAuthentication is responsible for getting a token and signing in.
func (authenticationObj *AuthenticationObj) GetPasswordSafeAuthentication() (entities.SignApinResponse, error) {
	var accessToken string = ""
	var err error

	if authenticationObj.clientId != "" && authenticationObj.clientSecret != "" {
		accessToken, err = authenticationObj.GetToken(authenticationObj.ApiUrl.JoinPath("Auth/connect/token").String(), authenticationObj.clientId, authenticationObj.clientSecret)
		if err != nil {
			return entities.SignApinResponse{}, err
		}
	}

	signApinResponse, err := authenticationObj.SignAppin(authenticationObj.ApiUrl.JoinPath("Auth/SignAppIn").String(), accessToken, authenticationObj.apiKey)
	if err != nil {
		return entities.SignApinResponse{}, err
	}

	return signApinResponse, nil
}

// GetToken is responsible for getting a token from the PS API.
func (authenticationObj *AuthenticationObj) GetToken(endpointUrl string, clientId string, clientSecret string) (string, error) {

	params := url.Values{}
	params.Add("client_id", clientId)
	params.Add("client_secret", clientSecret)
	params.Add("grant_type", "client_credentials")

	var body io.ReadCloser
	var technicalError error
	var businessError error

	var buffer bytes.Buffer
	buffer.WriteString(params.Encode())

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(endpointUrl, "POST", buffer, "GetToken", "", "")
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return "", err
	}

	responseString := string(bodyBytes)

	var data entities.GetTokenResponse

	err = json.Unmarshal([]byte(responseString), &data)
	if err != nil {
		authenticationObj.log.Error(err.Error())
		return "", err
	}

	authenticationObj.log.Debug("Successfully retrieved token")

	return data.AccessToken, nil

}

// SignAppin is responsible for creating a PS API session.
func (authenticationObj *AuthenticationObj) SignAppin(endpointUrl string, accessToken string, apiKey string) (entities.SignApinResponse, error) {

	var userObject entities.SignApinResponse
	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	err := backoff.Retry(func() error {
		body, scode, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(endpointUrl, "POST", bytes.Buffer{}, "SignAppin", accessToken, apiKey)
		if scode == 0 {
			return nil
		}
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if err != nil {
		return entities.SignApinResponse{}, err
	}

	if scode == 0 {
		return entities.SignApinResponse{}, technicalError
	}

	if businessError != nil {
		return entities.SignApinResponse{}, businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return entities.SignApinResponse{}, err
	}

	err = json.Unmarshal(bodyBytes, &userObject)

	if err != nil {
		authenticationObj.log.Error(err.Error())
		return entities.SignApinResponse{}, err
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

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(authenticationObj.ApiUrl.JoinPath("Auth/Signout").String(), "POST", bytes.Buffer{}, "SignOut", "", "")
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	if businessError != nil {
		authenticationObj.log.Error(businessError.Error())
		return businessError
	}

	if body != nil {
		defer body.Close()
	}

	defer authenticationObj.HttpClient.HttpClient.CloseIdleConnections()
	authenticationObj.log.Info("Successfully Signed out.")
	return nil
}
