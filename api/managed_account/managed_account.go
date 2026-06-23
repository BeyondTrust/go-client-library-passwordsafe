// Copyright 2025 BeyondTrust. All rights reserved.
// Package managed_accounts implements Get managed account logic
package managed_accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
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
	return managedAccountObj.GetSecretsWithContext(context.Background(), secretPaths, separator)
}

// GetSecretsWithContext is responsible for getting a list of managed account secret values based on the list of systems and account names.
func (managedAccountObj *ManagedAccountstObj) GetSecretsWithContext(ctx context.Context, secretPaths []string, separator string) (map[string]string, error) {
	return managedAccountObj.ManageAccountFlowWithContext(ctx, secretPaths, separator)
}

// GetSecret returns secret value for a specific System Name and Account Name.
func (managedAccountObj *ManagedAccountstObj) GetSecret(secretPath string, separator string) (string, error) {
	return managedAccountObj.GetSecretWithContext(context.Background(), secretPath, separator)
}

// GetSecretWithContext returns secret value for a specific System Name and Account Name.
func (managedAccountObj *ManagedAccountstObj) GetSecretWithContext(ctx context.Context, secretPath string, separator string) (string, error) {
	managedAccountList := []string{}
	secrets, err := managedAccountObj.ManageAccountFlowWithContext(ctx, append(managedAccountList, secretPath), separator)
	secretValue := secrets[secretPath]
	return secretValue, err
}

// ManageAccountFlow is responsible for creating a dictionary of managed account system/name and secret key-value pairs.
func (managedAccountObj *ManagedAccountstObj) ManageAccountFlow(secretsToRetrieve []string, separator string) (map[string]string, error) {
	return managedAccountObj.ManageAccountFlowWithContext(context.Background(), secretsToRetrieve, separator)
}

// ManageAccountFlowWithContext is responsible for creating a dictionary of managed account system/name and secret key-value pairs.
func (managedAccountObj *ManagedAccountstObj) ManageAccountFlowWithContext(ctx context.Context, secretsToRetrieve []string, separator string) (map[string]string, error) {

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
		managedAccount, err := managedAccountObj.ManagedAccountGetWithContext(ctx, systemName, accountName, ManagedAccountGetUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		ManagedAccountCreateRequestUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Requests").String()
		requestId, err := managedAccountObj.ManagedAccountCreateRequestWithContext(ctx, managedAccount.SystemId, managedAccount.AccountId, ManagedAccountCreateRequestUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		CredentialByRequestIdUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Credentials", requestId).String()
		secret, err := managedAccountObj.CredentialByRequestIdWithContext(ctx, requestId, CredentialByRequestIdUrl)
		if err != nil {
			saveLastErr = err
			managedAccountObj.log.Error(fmt.Sprintf("%v secretsPath: %v %v %v", err.Error(), systemName, separator, accountName))
			continue
		}

		ManagedAccountRequestCheckInUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("Requests", requestId, "checkin").String()
		_, err = managedAccountObj.ManagedAccountRequestCheckInWithContext(ctx, requestId, ManagedAccountRequestCheckInUrl)

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
	return managedAccountObj.ManagedAccountGetWithContext(context.Background(), systemName, accountName, url)
}

// ManagedAccountGetWithContext is responsible for retrieving a managed account secret based on the system and name.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountGetWithContext(ctx context.Context, systemName string, accountName string, url string) (entities.ManagedAccount, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.ManagedAccountGet,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
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

	defer func() { _ = body.Close() }()
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
	return managedAccountObj.ManagedAccountCreateRequestWithContext(context.Background(), systemName, accountName, url)
}

// ManagedAccountCreateRequestWithContext calls Secret Safe API Requests endpoint and returns a request Id as string.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountCreateRequestWithContext(ctx context.Context, systemName int, accountName int, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "POST", url)
	managedAccountObj.log.Debug(messageLog)

	data := fmt.Sprintf(`{"SystemID":%v, "AccountID":%v, "DurationMinutes":5, "Reason":"Tesr", "ConflictOption": "reuse"}`, systemName, accountName)
	b := bytes.NewBufferString(data)

	return managedAccountObj.sendRequestAndGetSingleString(ctx, "POST", url, constants.ManagedAccountCreateRequest, *b)

}

// CredentialByRequestId calls Secret Safe API Credentials/<request_id>
// enpoint and returns secret value by request Id.
func (managedAccountObj *ManagedAccountstObj) CredentialByRequestId(requestId string, url string) (string, error) {
	return managedAccountObj.CredentialByRequestIdWithContext(context.Background(), requestId, url)
}

// CredentialByRequestIdWithContext calls Secret Safe API Credentials/<request_id>
// endpoint and returns secret value by request Id.
func (managedAccountObj *ManagedAccountstObj) CredentialByRequestIdWithContext(ctx context.Context, requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(strings.ReplaceAll(messageLog, requestId, "****"))
	return managedAccountObj.sendRequestAndGetSingleString(ctx, "GET", url, constants.CredentialByRequestId, bytes.Buffer{})

}

// ManagedAccountRequestCheckIn calls Secret Safe API "Requests/<request_id>/checkin enpoint.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountRequestCheckIn(requestId string, url string) (string, error) {
	return managedAccountObj.ManagedAccountRequestCheckInWithContext(context.Background(), requestId, url)
}

// ManagedAccountRequestCheckInWithContext calls Secret Safe API "Requests/<request_id>/checkin endpoint.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountRequestCheckInWithContext(ctx context.Context, requestId string, url string) (string, error) {
	messageLog := fmt.Sprintf("%v %v", "PUT", url)
	managedAccountObj.log.Debug(strings.ReplaceAll(messageLog, requestId, "****"))

	data := "{}"
	b := bytes.NewBufferString(data)

	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  "PUT",
		Body:        *b,
		Method:      constants.ManagedAccountRequestCheckIn,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		_, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
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
	return managedAccountObj.ManageAccountCreateFlowWithContext(context.Background(), systemNameTarget, accountDetails)
}

// ManageAccountCreateFlowWithContext is responsible for creating a managed accounts in Password Safe.
func (managedAccountObj *ManagedAccountstObj) ManageAccountCreateFlowWithContext(ctx context.Context, systemNameTarget string, accountDetails entities.AccountDetails) (entities.CreateManagedAccountsResponse, error) {

	var managedSystem *entities.ManagedSystemResponse
	var createResponse entities.CreateManagedAccountsResponse

	accountDetails, err := utils.ValidateCreateManagedAccountInput(accountDetails)

	if err != nil {
		return createResponse, err
	}

	ManagedAccountSystemUrl := managedAccountObj.authenticationObj.ApiUrl.JoinPath("ManagedSystems").String()
	managedSystemGetSystemsResponse, err := managedAccountObj.ManagedSystemGetSystemsWithContext(ctx, ManagedAccountSystemUrl)

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
	createResponse, err = managedAccountObj.ManagedAccountCreateManagedAccountWithContext(ctx, accountDetails, ManagedAccountCreateManagedAccountUrl)

	if err != nil {
		return createResponse, err
	}

	return createResponse, nil

}

// ManagedAccountCreateManagedAccount calls Secret Safe API Requests enpoint to create managed accounts.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountCreateManagedAccount(accountDetails entities.AccountDetails, url string) (entities.CreateManagedAccountsResponse, error) {
	return managedAccountObj.ManagedAccountCreateManagedAccountWithContext(context.Background(), accountDetails, url)
}

// ManagedAccountCreateManagedAccountWithContext calls Secret Safe API Requests endpoint to create managed accounts.
func (managedAccountObj *ManagedAccountstObj) ManagedAccountCreateManagedAccountWithContext(ctx context.Context, accountDetails entities.AccountDetails, url string) (entities.CreateManagedAccountsResponse, error) {
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

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      constants.ManagedAccountCreateManagedAccount,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	var CreateManagedAccountsResponse entities.CreateManagedAccountsResponse

	if technicalError != nil {
		return entities.CreateManagedAccountsResponse{}, technicalError
	}

	if businessError != nil {
		return entities.CreateManagedAccountsResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
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
	return managedAccountObj.ManagedSystemGetSystemsWithContext(context.Background(), url)
}

// ManagedSystemGetSystemsWithContext is responsible for retrieving managed systems list.
func (managedAccountObj *ManagedAccountstObj) ManagedSystemGetSystemsWithContext(ctx context.Context, url string) ([]entities.ManagedSystemResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", url)
	managedAccountObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.ManagedSystemGetSystems,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
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

	defer func() { _ = body.Close() }()
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

// GetManagedAccountsListFlow get managed accounts list.
func (managedAccountObj *ManagedAccountstObj) GetManagedAccountsListFlow() ([]entities.ManagedAccount, error) {
	return managedAccountObj.GetManagedAccountsListFlowWithContext(context.Background())
}

// GetManagedAccountsListFlowWithContext gets managed accounts list.
func (managedAccountObj *ManagedAccountstObj) GetManagedAccountsListFlowWithContext(ctx context.Context) ([]entities.ManagedAccount, error) {
	return managedAccountObj.GetManagedAccountsListWithContext(ctx, "ManagedAccounts", constants.ManagedAccountCreate)
}

// GetManagedAccountsList call ManagedAccounts enpoint
// and returns managed accounts list
func (managedAccountObj *ManagedAccountstObj) GetManagedAccountsList(endpointPath string, method string) ([]entities.ManagedAccount, error) {
	return managedAccountObj.GetManagedAccountsListWithContext(context.Background(), endpointPath, method)
}

// GetManagedAccountsListWithContext calls ManagedAccounts endpoint
// and returns managed accounts list
func (managedAccountObj *ManagedAccountstObj) GetManagedAccountsListWithContext(ctx context.Context, endpointPath string, method string) ([]entities.ManagedAccount, error) {

	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	managedAccountObj.log.Debug(messageLog)

	url := managedAccountObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var managedAccountList []entities.ManagedAccount

	response, err := managedAccountObj.authenticationObj.HttpClient.GetGeneralListWithContext(ctx, url, managedAccountObj.authenticationObj.ApiVersion, method, managedAccountObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		return managedAccountList, err
	}

	err = json.Unmarshal(response, &managedAccountList)

	if err != nil {
		return managedAccountList, err
	}

	if len(managedAccountList) == 0 {
		return managedAccountList, fmt.Errorf("empty managed accounts list")
	}

	return managedAccountList, nil

}

// sendRequestAndGetSingleString send a request and get the response as string.
func (managedAccountObj *ManagedAccountstObj) sendRequestAndGetSingleString(ctx context.Context, httpMethod string, url string, method string, b bytes.Buffer) (string, error) {

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  httpMethod,
		Body:        b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}
	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)
	if technicalError != nil {
		return "", technicalError
	}
	if businessError != nil {
		return "", businessError
	}
	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	responseString := string(bodyBytes)
	return responseString, nil

}

// DeleteManagedAccountById deletes a managed account by its ID.
func (managedAccountObj *ManagedAccountstObj) DeleteManagedAccountById(managedAccountID int) error {
	return managedAccountObj.DeleteManagedAccountByIdWithContext(context.Background(), managedAccountID)
}

// DeleteManagedAccountByIdWithContext deletes a managed account by its ID.
func (managedAccountObj *ManagedAccountstObj) DeleteManagedAccountByIdWithContext(ctx context.Context, managedAccountID int) error {
	url := managedAccountObj.authenticationObj.ApiUrl.JoinPath("ManagedAccounts", strconv.Itoa(managedAccountID)).String()
	messageLog := fmt.Sprintf("%v %v", "DELETE", url)
	managedAccountObj.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Ctx:         ctx,
		Url:         url,
		HttpMethod:  "DELETE",
		Body:        bytes.Buffer{},
		Method:      constants.ManagedAccountDelete,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		_, _, technicalError, businessError = managedAccountObj.authenticationObj.HttpClient.CallSecretSafeAPIWithContext(ctx, *callSecretSafeAPIObj)
		return technicalError
	}, managedAccountObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return technicalError
	}
	if businessError != nil {
		return businessError
	}
	return nil
}
