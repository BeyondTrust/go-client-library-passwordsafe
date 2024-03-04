// Copyright 2024 BeyondTrust. All rights reserved.
// Package client implements functions to call Beyondtrust Secret Safe API.
package authentication

import (
	"bytes"
	"encoding/json"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"io"

	"net/url"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
)

// AuthenticationObj responsbile for authentication request data.
type AuthenticationObj struct {
	ApiUrl             url.URL
	clientId           string
	clientSecret       string
	HttpClient         utils.HttpClientObj
	ExponentialBackOff *backoff.ExponentialBackOff
	log                logging.Logger
}

// Authenticate is responsible for Auth configuration.
// Prerequisites - use input validation methods before using this class.
func Authenticate(httpClient utils.HttpClientObj, endpointUrl string, clientId string, clientSecret string, logger logging.Logger, retryMaxElapsedTimeSeconds int) (*AuthenticationObj, error) {

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(retryMaxElapsedTimeSeconds) * time.Second
	backoffDefinition.RandomizationFactor = 0.5
	apiUrl, _ := url.Parse(endpointUrl)
	authenticationObj := &AuthenticationObj{
		ApiUrl:             *apiUrl,
		HttpClient:         httpClient,
		clientId:           clientId,
		clientSecret:       clientSecret,
		ExponentialBackOff: backoffDefinition,
		log:                logger,
	}

	return authenticationObj, nil
}

// GetPasswordSafeAuthentication is responsible for getting a token and signing in.
func (authenticationObj *AuthenticationObj) GetPasswordSafeAuthentication() (entities.SignApinResponse, error) {

	accessToken, err := authenticationObj.GetToken(authenticationObj.ApiUrl.JoinPath("Auth/connect/token").String(), authenticationObj.clientId, authenticationObj.clientSecret)
	if err != nil {
		return entities.SignApinResponse{}, err
	}
	signApinResponse, err := authenticationObj.SignAppin(authenticationObj.ApiUrl.JoinPath("Auth/SignAppIn").String(), accessToken)
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
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(endpointUrl, "POST", buffer, "GetToken", "")
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
func (authenticationObj *AuthenticationObj) SignAppin(endpointUrl string, accessToken string) (entities.SignApinResponse, error) {

	var userObject entities.SignApinResponse
	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	err := backoff.Retry(func() error {
		body, scode, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(endpointUrl, "POST", bytes.Buffer{}, "SignAppin", accessToken)
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
func (authenticationObj *AuthenticationObj) SignOut(url string) error {
	authenticationObj.log.Debug(url)

	var technicalError error
	var businessError error
	var body io.ReadCloser

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = authenticationObj.HttpClient.CallSecretSafeAPI(url, "POST", bytes.Buffer{}, "SignOut", "")
		return technicalError
	}, authenticationObj.ExponentialBackOff)

	defer body.Close()
	if businessError != nil {
		authenticationObj.log.Error(businessError.Error())
		return businessError
	}

	defer authenticationObj.HttpClient.HttpClient.CloseIdleConnections()
	authenticationObj.log.Info("Successfully Signed out.")
	return nil
}
