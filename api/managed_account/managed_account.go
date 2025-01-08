// Copyright 2024 BeyondTrust. All rights reserved.
// Package managed_accounts implements Get managed account logic
package managed_accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	backoff "github.com/cenkalti/backoff/v4"
)

// ManagedAccountstObj responsible for session requests.
type ManagedAccountstObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewManagedAccountObj creates managed account obj
func NewManagedAccountObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*ManagedAccountstObj, error) {
	managedAccountObj := &ManagedAccountstObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return managedAccountObj, nil
}

// GetSecrets is responsible for getting a list of managed account secret values based on the list of systems and account names.
func (managedAccountObj *ManagedAccountstObj) GetSecrets(secretPaths []string, separator string) (map[string]string, error) {
	return managedAccountObj.ManageAccountFlow(secretPaths, separator)
}

// GetSecret returns secret value for a specific System Name and Account Name.
func (managedAccountObj *ManagedAccountstObj) GetSecret(secretPath string, separator string) (string, error) {
	managedAccountList := []string{}
	secrets, err := managedAccountObj.ManageAccountFlow(append(managedAccountList, secretPath), separator)
	secretValue := secrets[secretPath]
	return secretValue, err
}

// ManageAccountFlow is responsible for creating a dictionary of managed account system/name and secret key-value pairs.
func (managedAccountObj *ManagedAccountstObj) ManageAccountFlow(secretsToRetrieve []string, separator string) (map[string]string, error) {

	secretsToRetrieve = utils.ValidatePaths(secretsToRetrieve, true, separator, managedAccountObj.log)
	managedAccountObj.log.Info(fmt.Sprintf("Retrieving %v Secrets", len(secretsToRetrieve)))
	secretDictionary := make(map[string]string)
	var saveLastErr error = nil

	if len(secretsToRetrieve) == 0 {
		return secretDictionary, errors.New("empty managed account list")
	}

	for _, secretToRetrieve := range secretsToRetrieve {
		retrievalData := strings.Split(secretToRetrieve, separator)
		systemName := retrievalData[0]
		accountName := retrievalData[1]

		v := url.Values{}
		v.Add("systemName", systemName)
		v.Add("accountName", accountName)

		var err error

		ManagedAccountGetUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("ManagedAccounts").String() + "?" + v.Encode()
		managedAccount, err := managedAccountObj.ManagedAccountGet(systemName, accountName, ManagedAccountGetUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		ManagedAccountCreateRequestUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Requests").String()
		requestId, err := managedAccountObj.ManagedAccountCreateRequest(managedAccount.SystemId, managedAccount.AccountId, ManagedAccountCreateRequestUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		CredentialByRequestIdUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Credentials", requestId).String()
		secret, err := managedAccountObj.CredentialByRequestId(requestId, CredentialByRequestIdUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		ManagedAccountRequestCheckInUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Requests", requestId, "checkin").String()
		_, err = managedAccountObj.ManagedAccountRequestCheckIn(requestId, ManagedAccountRequestCheckInUrl)

		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		secretValue, _ := strconv.Unquote(secret)
		secretDictionary[secretToRetrieve] = secretValue

	}

	return secretDictionary, saveLastErr
}

// ManagedAccountGet is responsible for retrieving a managed account secret based on the system and name.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountGet(systemName string, accountName string, url string) (entities.ManagedAccount, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "ManagedAccountGet", "", "", "application/json")
		if technicalError != nil {
			return technicalError
		}
		return nil

	}, managedAccountObj.authenticationObj.ExponentialBackOff)

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
		managedAccountObj.log.Error(err.Error())
		return entities.ManagedAccount{}, err
	}

	return managedAccountObject, nil

}

// ManagedAccountCreateRequest calls Secret Safe API Requests enpoint and returns a request Id as string.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountCreateRequest(systemName int, accountName int, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "POST", url)
	managedAccountObj.log.Debug(messageLog)

	data := fmt.Sprintf(`{"SystemID":%v, "AccountID":%v, "DurationMinutes":5, "Reason":"Tesr", "ConflictOption": "reuse"}`, systemName, accountName)
	b := bytes.NewBufferString(data)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "POST", *b, "ManagedAccountCreateRequest", "", "", "application/json")
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

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
func (managedAccountObj *ManagedAccountstObj) CredentialByRequestId(requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(strings.Replace(messageLog, requestId, "****", -1))

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "CredentialByRequestId", "", "", "application/json")
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		managedAccountObj.log.Error(err.Error())
		return "", err
	}

	responseString := string(bodyBytes)

	return responseString, nil
}

// ManagedAccountRequestCheckIn calls Secret Safe API "Requests/<request_id>/checkin enpoint.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountRequestCheckIn(requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "PUT", url)
	managedAccountObj.log.Debug(strings.Replace(messageLog, requestId, "****", -1))

	data := "{}"
	b := bytes.NewBufferString(data)

	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		_, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "PUT", *b, "ManagedAccountRequestCheckIn", "", "", "application/json")
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	return "", nil
}

// ManageAccountCreateFlow is responsible for creating a managed accounts in Password Safe.
func (managedAccountObj *ManagedAccountstObj) ManageAccountCreateFlow(systemNameTarget string, accountDetails entities.AccountDetails) (entities.CreateManagedAccountsResponse, error) {

	var managedSystem *entities.ManagedSystemResponse
	var createResponse entities.CreateManagedAccountsResponse

	accountDetails, err := utils.ValidateCreateManagedAccountInput(accountDetails)

	if err != nil {
		return createResponse, err
	}

	ManagedAccountSystemUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("ManagedSystems").String()
	managedSystemGetSystemsResponse, err := managedAccountObj.ManagedSystemGetSystems(ManagedAccountSystemUrl)

	if err != nil {
		return createResponse, err
	}

	for _, v := range managedSystemGetSystemsResponse {
		if v.SystemName == systemNameTarget {
			managedSystem = &v
			break
		}
	}

	if managedSystem == nil {
		return createResponse, fmt.Errorf("managed system %v was not found in managed system list", systemNameTarget)
	}

	ManagedAccountCreateManagedAccountUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("ManagedSystems", fmt.Sprintf("%d", managedSystem.ManagedSystemID), "ManagedAccounts").String()
	createResponse, err = managedAccountObj.ManagedAccountCreateManagedAccount(accountDetails, ManagedAccountCreateManagedAccountUrl)

	if err != nil {
		return createResponse, err
	}

	return createResponse, nil

}

// ManagedAccountCreateManagedAccount calls Secret Safe API Requests enpoint to create managed accounts.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountCreateManagedAccount(accountDetails entities.AccountDetails, url string) (entities.CreateManagedAccountsResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "POST", url)
	managedAccountObj.log.Debug(messageLog)

	accountDetailsJson, err := json.Marshal(accountDetails)
	if err != nil {
		return entities.CreateManagedAccountsResponse{}, err
	}

	accountDetailsJsonString := string(accountDetailsJson)

	b := bytes.NewBufferString(accountDetailsJsonString)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "POST", *b, "ManagedAccountCreateManagedAccount", "", "", "application/json")
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	var CreateManagedAccountsResponse entities.CreateManagedAccountsResponse

	if technicalError != nil {
		return entities.CreateManagedAccountsResponse{}, technicalError
	}

	if businessError != nil {
		return entities.CreateManagedAccountsResponse{}, businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.CreateManagedAccountsResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &CreateManagedAccountsResponse)

	if err != nil {
		managedAccountObj.log.Error(err.Error())
		return entities.CreateManagedAccountsResponse{}, err
	}

	return CreateManagedAccountsResponse, nil

}

// ManagedAccountGetSystem is responsible for retrieving managed systems list
func (managedAccountObj *ManagedAccountstObj) ManagedSystemGetSystems(url string) ([]entities.ManagedSystemResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPI(url, "GET", bytes.Buffer{}, "ManagedSystemGetSystems", "", "", "application/json")
		if technicalError != nil {
			return technicalError
		}
		return nil

	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	var managedSystemObject []entities.ManagedSystemResponse

	if technicalError != nil {
		return managedSystemObject, technicalError
	}

	if businessError != nil {
		return managedSystemObject, businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return managedSystemObject, err
	}

	err = json.Unmarshal(bodyBytes, &managedSystemObject)
	if err != nil {
		managedAccountObj.log.Error(err.Error())
		return managedSystemObject, err
	}

	if len(managedSystemObject) == 0 {
		return managedSystemObject, fmt.Errorf("empty System Account List")
	}

	return managedSystemObject, nil

}
