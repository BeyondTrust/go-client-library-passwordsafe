// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements Get secret logic
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"io"
	"net/url"
	"strings"

	backoff "github.com/cenkalti/backoff/v4"
)

type SecretObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewSecretObj creates secret obj
func NewSecretObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*SecretObj, error) {
	secretObj := &SecretObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return secretObj, nil
}

// GetSecrets returns secret value for a path and title list.
func (secretObj *SecretObj) GetSecrets(secretsList []string, separator string) (map[string]string, error) {
	if separator == "" {
		separator = ""
	}
	return secretObj.GetSecretFlow(secretsList, separator)
}

// GetSecret returns secret value for a specific path and title.
func (secretObj *SecretObj) GetSecret(secretsList []string, separator string) (map[string]string, error) {
	return secretObj.GetSecretFlow(secretsList, separator)
}

// GetSecretFlow returns secret value for a specific path and title list
func (secretObj *SecretObj) GetSecretFlow(secretsToRetrieve []string, separator string) (map[string]string, error) {

	secretDictionary := make(map[string]string)

	for _, secretToRetrieve := range secretsToRetrieve {
		secretData := strings.Split(secretToRetrieve, separator)

		secretPath := secretData[0]
		secretTitle := secretData[1]

		secret, err := secretObj.SecretGetSecretByPath(secretPath, secretTitle, separator, "secrets-safe/secrets")

		if err != nil {
			return nil, err
		}

		// When secret type is FILE, it calls SecretGetFileSecret method.
		if strings.ToUpper(secret.SecretType) == "FILE" {
			fileSecretContent, err := secretObj.SecretGetFileSecret(secret.Id, "secrets-safe/secrets/")
			if err != nil {
				secretObj.log.Error(err.Error())
				return nil, err
			}

			secretDictionary[secretToRetrieve] = fileSecretContent
		}
		secretDictionary[secretToRetrieve] = secret.Password

	}

	return secretDictionary, nil
}

// SecretGetSecretByPath returns secret object for a specific path, title.
func (secretObj *SecretObj) SecretGetSecretByPath(secretPath string, secretTitle string, separator string, endpointPath string) (entities.Secret, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	secretObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	params := url.Values{}
	params.Add("path", secretPath)
	params.Add("title", secretTitle)

	url := fmt.Sprintf("%s%s?%s", secretObj.authenticationObj.ApiUrl, endpointPath, params.Encode())

	technicalError = backoff.Retry(func() error {
		body, technicalError, businessError, scode = secretObj.authenticationObj.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "SecretGetSecretByPath", "")
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.Secret{}, technicalError
	}

	if businessError != nil {
		return entities.Secret{}, businessError
	}

	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.Secret{}, err
	}

	var SecretObjectList []entities.Secret
	err = json.Unmarshal([]byte(bodyBytes), &SecretObjectList)
	if err != nil {
		err = errors.New(err.Error() + ", Ensure Password Safe version is 23.1 or greater.")
		return entities.Secret{}, err
	}

	if len(SecretObjectList) == 0 {
		scode = 404
		err = fmt.Errorf("Error %v: StatusCode: %v ", "SecretGetSecretByPath, Secret was not found", scode)
		return entities.Secret{}, err
	}

	return SecretObjectList[0], nil
}

// SecretGetFileSecret call secrets-safe/secrets/<secret_id>/file/download enpoint
// and returns file secret value.
func (secretObj *SecretObj) SecretGetFileSecret(secretId string, endpointPath string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	secretObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	url := fmt.Sprintf("%s%s%s%s", secretObj.authenticationObj.ApiUrl, endpointPath, secretId, "/file/download")

	technicalError = backoff.Retry(func() error {
		body, technicalError, businessError, _ = secretObj.authenticationObj.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "SecretGetFileSecret", "")
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	responseData, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	responseString := string(responseData)
	return responseString, nil

}
