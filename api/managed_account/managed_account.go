// Copyright 2024 BeyondTrust. All rights reserved.
// Package managed_accounts implements Get managed account logic

package managed_accounts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	"go-client-library-passwordsafe/api/entities"
	"go-client-library-passwordsafe/api/logging"
	"go-client-library-passwordsafe/api/utils"
	"io"
	"strconv"
	"strings"

	backoff "github.com/cenkalti/backoff/v4"
)

type ManagedAccountstObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewManagedAccountObj creates managed account obj
func NewManagedAccountObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*ManagedAccountstObj, error) {
	managedAccounObj := &ManagedAccountstObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return managedAccounObj, nil
}

// GetSecrets is responsible for getting a list of managed account secret values based on the list of systems and account names.
func (managedAccounObj *ManagedAccountstObj) GetSecrets(secretPaths []string, separator string) (map[string]string, error) {
	if separator == "" {
		separator = ""
	}
	return managedAccounObj.ManageAccountFlow(secretPaths, separator, make(map[string]string))
}

// GetSecret returns secret value for a specific System Name and Account Name.
func (managedAccounObj *ManagedAccountstObj) GetSecret(secretPath string, separator string) (map[string]string, error) {
	managedAccountList := []string{}
	return managedAccounObj.ManageAccountFlow(append(managedAccountList, secretPath), separator, make(map[string]string))
}

// ManageAccountFlow is responsible for creating a dictionary of managed account system/name and secret key-value pairs.
func (managedAccounObj *ManagedAccountstObj) ManageAccountFlow(secretsToRetrieve []string, separator string, paths map[string]string) (map[string]string, error) {

	secretDictionary := make(map[string]string)

	secretsToRetrieve, _ = utils.ValidatePaths(secretsToRetrieve, separator, managedAccounObj.log)

	for _, secretToRetrieve := range secretsToRetrieve {
		secretData := strings.Split(secretToRetrieve, separator)

		systemName := secretData[0]
		accountName := secretData[1]

		if len(paths) == 0 {
			paths["SignAppinPath"] = "Auth/SignAppin"
			paths["SignAppOutPath"] = "Auth/Signout"
			paths["ManagedAccountGetPath"] = fmt.Sprintf("ManagedAccounts?systemName=%v&accountName=%v", systemName, accountName)
			paths["ManagedAccountCreateRequestPath"] = "Requests"
			paths["CredentialByRequestIdPath"] = "Credentials/%v"
			paths["ManagedAccountRequestCheckInPath"] = "Requests/%v/checkin"
		}

		var err error

		ManagedAccountGetUrl := managedAccounObj.RequestPath(paths["ManagedAccountGetPath"])
		managedAccount, err := managedAccounObj.ManagedAccountGet(systemName, accountName, ManagedAccountGetUrl)
		if err != nil {
			managedAccounObj.log.Error(err.Error())
			return nil, err
		}

		ManagedAccountCreateRequestUrl := managedAccounObj.RequestPath(paths["ManagedAccountCreateRequestPath"])
		requestId, err := managedAccounObj.ManagedAccountCreateRequest(managedAccount.SystemId, managedAccount.AccountId, ManagedAccountCreateRequestUrl)
		if err != nil {
			managedAccounObj.log.Error(err.Error())
			return nil, err
		}

		CredentialByRequestIdUrl := managedAccounObj.RequestPath(fmt.Sprintf(paths["CredentialByRequestIdPath"], requestId))
		secret, err := managedAccounObj.CredentialByRequestId(requestId, CredentialByRequestIdUrl)
		if err != nil {
			managedAccounObj.log.Error(err.Error())
			return nil, err
		}

		ManagedAccountRequestCheckInPath := fmt.Sprintf(paths["ManagedAccountRequestCheckInPath"], requestId)
		ManagedAccountRequestCheckInUrl := managedAccounObj.RequestPath(ManagedAccountRequestCheckInPath)
		_, err = managedAccounObj.ManagedAccountRequestCheckIn(requestId, ManagedAccountRequestCheckInUrl)

		if err != nil {
			managedAccounObj.log.Error(err.Error())
			return nil, err
		}

		secretValue, _ := strconv.Unquote(secret)
		secretDictionary[secretToRetrieve] = secretValue

	}
	return secretDictionary, nil
}

// ManagedAccountGet is responsible for retrieving a managed account secret based on the system and name.
func (managedAccounObj *ManagedAccountstObj) ManagedAccountGet(systemName string, accountName string, url string) (entities.ManagedAccount, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccounObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, technicalError, businessError, _ = managedAccounObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "ManagedAccountGet", "")
		if technicalError != nil {
			return technicalError
		}
		return nil

	}, managedAccounObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.ManagedAccount{}, technicalError
	}

	if businessError != nil {
		return entities.ManagedAccount{}, businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.ManagedAccount{}, err
	}

	var managedAccountObject entities.ManagedAccount
	err = json.Unmarshal(bodyBytes, &managedAccountObject)
	if err != nil {
		managedAccounObj.log.Error(err.Error())
		return entities.ManagedAccount{}, err
	}

	return managedAccountObject, nil

}

// ManagedAccountCreateRequest calls Secret Safe API Requests enpoint and returns a request Id as string.
func (managedAccounObj *ManagedAccountstObj) ManagedAccountCreateRequest(systemName int, accountName int, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "POST", url)
	managedAccounObj.log.Debug(messageLog)

	data := fmt.Sprintf(`{"SystemID":%v, "AccountID":%v, "DurationMinutes":5, "Reason":"Tesr", "ConflictOption": "reuse"}`, systemName, accountName)
	b := bytes.NewBufferString(data)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, technicalError, businessError, _ = managedAccounObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "POST", *b, "ManagedAccountCreateRequest", "")
		return technicalError
	}, managedAccounObj.authenticationObj.ExponentialBackOff)

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

	return responseString, nil

}

// CredentialByRequestId calls Secret Safe API Credentials/<request_id>
// enpoint and returns secret value by request Id.
func (managedAccounObj *ManagedAccountstObj) CredentialByRequestId(requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccounObj.log.Debug(strings.Replace(messageLog, requestId, "****", -1))

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, technicalError, businessError, _ = managedAccounObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "CredentialByRequestId", "")
		return technicalError
	}, managedAccounObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		managedAccounObj.log.Error(err.Error())
		return "", err
	}

	if err != nil {
		return "", err
	}

	responseString := string(bodyBytes)

	return responseString, nil

}

// ManagedAccountRequestCheckIn calls Secret Safe API "Requests/<request_id>/checkin enpoint.
func (managedAccounObj *ManagedAccountstObj) ManagedAccountRequestCheckIn(requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "PUT", url)
	managedAccounObj.log.Debug(strings.Replace(messageLog, requestId, "****", -1))

	data := "{}"
	b := bytes.NewBufferString(data)

	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		_, technicalError, businessError, _ = managedAccounObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "PUT", *b, "ManagedAccountRequestCheckIn", "")
		return technicalError
	}, managedAccounObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	return "", nil
}

// requestPath Build endpint path.
func (managedAccounObj *ManagedAccountstObj) RequestPath(path string) string {
	return fmt.Sprintf("%v/%v", managedAccounObj.authenticationObj.ApiUrl, path)
}
