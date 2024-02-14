// Copyright 2024 BeyondTrust. All rights reserved.
// Package client implements functions to call Beyondtrust Secret Safe API.
package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"io"

	"net/http"
	"net/url"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
)

type AuthenticationObj struct {
	ApiUrl             string
	clientId           string
	clientSecret       string
	httpClient         *http.Client
	ExponentialBackOff *backoff.ExponentialBackOff
	signApinResponse   entities.SignApinResponse
	log                logging.Logger
}

// Authenticate in PS API
func Authenticate(httpClient *http.Client, endpointUrl string, clientId string, clientSecret string, logger logging.Logger, maxElapsedTime int) (*AuthenticationObj, error) {

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(maxElapsedTime) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	// Client
	var client = httpClient

	authenticationObj := &AuthenticationObj{
		ApiUrl:             endpointUrl,
		httpClient:         client,
		clientId:           clientId,
		clientSecret:       clientSecret,
		ExponentialBackOff: backoffDefinition,
		log:                logger,
	}

	return authenticationObj, nil
}

// GetPasswordSafeAuthentication call get token and sign app endpoint
func (c *AuthenticationObj) GetPasswordSafeAuthentication() (entities.SignApinResponse, error) {
	accessToken, err := c.GetToken(fmt.Sprintf("%v%v", c.ApiUrl, "Auth/connect/token"), c.clientId, c.clientSecret)
	if err != nil {
		return entities.SignApinResponse{}, err
	}
	signApinResponse, err := c.SignAppin(fmt.Sprintf("%v%v", c.ApiUrl, "Auth/SignAppIn"), accessToken)
	if err != nil {
		return entities.SignApinResponse{}, err
	}
	return signApinResponse, nil
}

// GetToken get token from PS API
func (c *AuthenticationObj) GetToken(endpointUrl string, clientId string, clientSecret string) (string, error) {

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
		body, technicalError, businessError, _ = c.CallSecretSafeAPI(endpointUrl, "POST", buffer, "GetToken", "")
		return technicalError
	}, c.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return "", err
	}

	responseString := string(bodyBytes)

	var data entities.GetTokenResponse

	err = json.Unmarshal([]byte(responseString), &data)
	if err != nil {
		c.log.Error(err.Error())
		return "", err
	}

	return data.AccessToken, nil

}

// SignAppin Signs app in  PS API
func (c *AuthenticationObj) SignAppin(endpointUrl string, accessToken string) (entities.SignApinResponse, error) {

	var userObject entities.SignApinResponse
	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	err := backoff.Retry(func() error {
		body, technicalError, businessError, scode = c.CallSecretSafeAPI(endpointUrl, "POST", bytes.Buffer{}, "SignAppin", accessToken)
		if scode == 0 {
			return nil
		}
		return technicalError
	}, c.ExponentialBackOff)

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
		c.log.Error(err.Error())
		return entities.SignApinResponse{}, err
	}

	return userObject, nil
}

// SignOut signs out Secret Safe API.
// Warn: should only be called one time for all data sources.
func (c *AuthenticationObj) SignOut(url string) error {
	c.log.Debug(url)

	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		_, technicalError, businessError, _ = c.CallSecretSafeAPI(url, "POST", bytes.Buffer{}, "SignOut", "")
		return technicalError
	}, c.ExponentialBackOff)

	if businessError != nil {
		c.log.Error(businessError.Error())
		return businessError
	}

	return nil
}

// CallSecretSafeAPI prepares http call
func (c *AuthenticationObj) CallSecretSafeAPI(url string, httpMethod string, body bytes.Buffer, method string, accesToken string) (io.ReadCloser, error, error, int) {
	response, technicalError, businessError, scode := c.HttpRequest(url, httpMethod, body, accesToken)
	if technicalError != nil {
		messageLog := fmt.Sprintf("Error in %v %v \n", method, technicalError)
		c.log.Error(messageLog)
	}

	if businessError != nil {
		messageLog := fmt.Sprintf("Error in %v: %v \n", method, businessError)
		c.log.Error(messageLog)
	}
	return response, technicalError, businessError, scode
}

// HttpRequest makes http request to he server
func (c *AuthenticationObj) HttpRequest(url string, method string, body bytes.Buffer, accesToken string) (closer io.ReadCloser, technicalError error, businessError error, scode int) {

	req, err := http.NewRequest(method, url, &body)
	if err != nil {
		return nil, err, nil, 0
	}
	req.Header = http.Header{
		"Content-Type": {"application/json"},
	}

	if accesToken != "" {
		req.Header.Set("Authorization", "Bearer "+accesToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Error(err.Error())
		return nil, err, nil, 0
	}

	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusRequestTimeout {
		err = fmt.Errorf("Error %v: StatusCode: %v, %v, %v", method, scode, err, body)
		c.log.Error(err.Error())
		return nil, err, nil, resp.StatusCode
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody := new(bytes.Buffer)
		respBody.ReadFrom(resp.Body)
		err = fmt.Errorf("got a non 200 status code: %v - %v", resp.StatusCode, respBody)
		return nil, nil, err, resp.StatusCode
	}

	return resp.Body, nil, nil, resp.StatusCode
}
