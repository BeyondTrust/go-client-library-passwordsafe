// Copyright 2025 BeyondTrust. All rights reserved.
// Package managed_systems implements functions to manage functional accounts in Password Safe.
package functional_accounts

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
)

type FunctionalAccount struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

var endpointPath = "FunctionalAccounts"

// NewFuncionalAccount creates FunctionalAccount Object.
func NewFuncionalAccount(authentication authentication.AuthenticationObj, logger logging.Logger) (*FunctionalAccount, error) {
	functionalAccountObj := &FunctionalAccount{
		log:               logger,
		authenticationObj: authentication,
	}
	return functionalAccountObj, nil
}

// CreateFunctionalAccountFlow is responsible for creating functional accounts in Password Safe.
func (functionalAccount *FunctionalAccount) CreateFunctionalAccountFlow(functionalAccountDetails entities.FunctionalAccountDetails) (entities.FunctionalAccountResponseCreate, error) {

	var functionalAccountResponse entities.FunctionalAccountResponseCreate
	var err error

	err = utils.ValidateData(functionalAccountDetails)
	if err != nil {
		return functionalAccountResponse, err
	}

	functionalAccountResponse, err = functionalAccount.createFunctionalAccount(constants.CreateManagedSystemByAssetId, "POST", endpointPath, functionalAccountDetails)

	if err != nil {
		return functionalAccountResponse, err
	}

	return functionalAccountResponse, nil

}

// GetFunctionalAccountsFlow is responsible for getting functional accounts list from Password Safe.
func (functionalAccount *FunctionalAccount) GetFunctionalAccountsFlow() ([]entities.FunctionalAccountResponseCreate, error) {

	var functionalAccountResponse []entities.FunctionalAccountResponseCreate
	var err error

	functionalAccountResponse, err = functionalAccount.GetFunctionalAccountsList(constants.GetFunctionalAccount, "GET", endpointPath)

	if err != nil {
		return functionalAccountResponse, err
	}

	return functionalAccountResponse, nil

}

// createFunctionalAccount calls Password Safe API enpoint to create functional account.
func (functionalAccount *FunctionalAccount) createFunctionalAccount(method string, httpMethod string, path string, functionalAccountDetails entities.FunctionalAccountDetails) (entities.FunctionalAccountResponseCreate, error) {

	var err error
	var functionalAccountResponse entities.FunctionalAccountResponseCreate

	// Convert payload to json string.
	objBytes, err := json.Marshal(functionalAccountDetails)
	if err != nil {
		return functionalAccountResponse, err
	}
	functionalAccountJson := string(objBytes)

	b := bytes.NewBufferString(functionalAccountJson)

	createManagedSystemUrl := functionalAccount.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", httpMethod, createManagedSystemUrl)
	functionalAccount.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createManagedSystemUrl,
		HttpMethod:  httpMethod,
		Body:        *b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  functionalAccount.authenticationObj.ApiVersion,
	}

	response, err := functionalAccount.authenticationObj.HttpClient.MakeRequest(callSecretSafeAPIObj, functionalAccount.authenticationObj.ExponentialBackOff)

	if err != nil {
		return functionalAccountResponse, err
	}

	err = json.Unmarshal(response, &functionalAccountResponse)
	if err != nil {
		return functionalAccountResponse, err
	}

	return functionalAccountResponse, nil

}

// GetFunctionalAccountsList calls Password Safe API enpoint to get functional accounts list.
func (functionalAccount *FunctionalAccount) GetFunctionalAccountsList(method string, httpMethod string, path string) ([]entities.FunctionalAccountResponseCreate, error) {

	var err error
	var functionalAccountResponse []entities.FunctionalAccountResponseCreate

	createManagedSystemUrl := functionalAccount.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", httpMethod, createManagedSystemUrl)
	functionalAccount.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createManagedSystemUrl,
		HttpMethod:  httpMethod,
		Body:        bytes.Buffer{},
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  functionalAccount.authenticationObj.ApiVersion,
	}

	response, err := functionalAccount.authenticationObj.HttpClient.MakeRequest(callSecretSafeAPIObj, functionalAccount.authenticationObj.ExponentialBackOff)

	if err != nil {
		return functionalAccountResponse, err
	}

	err = json.Unmarshal(response, &functionalAccountResponse)

	if err != nil {
		return functionalAccountResponse, err
	}

	return functionalAccountResponse, err

}
