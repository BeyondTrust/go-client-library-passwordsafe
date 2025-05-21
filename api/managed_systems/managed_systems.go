// Copyright 2025 BeyondTrust. All rights reserved.
// Package managed_systems implements functions to manage managed_systems in Password Safe.
package managed_systems

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	backoff "github.com/cenkalti/backoff/v4"
)

type ManagedSystemObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewManagedSystem creates ManagedSystemObj
func NewManagedSystem(authentication authentication.AuthenticationObj, logger logging.Logger) (*ManagedSystemObj, error) {
	managedSystemObj := &ManagedSystemObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return managedSystemObj, nil
}

// CreateManagedSystemByAssetIdFlow is responsible for creating managed_systems by Asset Id in Password Safe.
func (ManagedSystemObj *ManagedSystemObj) CreateManagedSystemByAssetIdFlow(assetId string, managedSystemDetailsInterface interface{}) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate
	var managedSystemJson string
	var err error

	if assetId == "" {
		return managedSystemResponse, errors.New("asset id is empty, please send a valid asset id")
	}

	switch managedSystemDetails := managedSystemDetailsInterface.(type) {

	// validate request body according to the API Version.
	case entities.ManagedSystemsByAssetIdDetailsConfig30, // v3.0
		entities.ManagedSystemsByAssetIdDetailsConfig31, // v3.1
		entities.ManagedSystemsByAssetIdDetailsConfig32: // v3.2
		err = utils.ValidateData(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}

		var bytes []byte

		// Convert object to json string.
		bytes, err = json.Marshal(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}
		managedSystemJson = string(bytes)
	}

	path := fmt.Sprintf("/Assets/%s/ManagedSystems", assetId)

	managedSystemResponse, err = ManagedSystemObj.createManagedSystem(constants.CreateManagedSystemByAssetId, path, managedSystemJson)

	if err != nil {
		return managedSystemResponse, err
	}

	return managedSystemResponse, nil

}

// CreateManagedSystemByWorkGroupIdFlow is responsible for creating managed_systems by WorkGroup Id in Password Safe.
func (ManagedSystemObj *ManagedSystemObj) CreateManagedSystemByWorkGroupIdFlow(workGroupId string, managedSystemDetailsInterface interface{}) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate
	var managedSystemJson string
	var err error

	if workGroupId == "" {
		return managedSystemResponse, errors.New("workGroup Id is empty, please send a valid workGroup Id")
	}

	switch managedSystemDetails := managedSystemDetailsInterface.(type) {

	// validate request body according to the API Version.
	case entities.ManagedSystemsByWorkGroupIdDetailsConfig30, // v3.0
		entities.ManagedSystemsByWorkGroupIdDetailsConfig31, // v3.1
		entities.ManagedSystemsByWorkGroupIdDetailsConfig32, // v3.2
		entities.ManagedSystemsByWorkGroupIdDetailsConfig33: // v3.3
		err = utils.ValidateData(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}

		var bytes []byte

		// Convert object to json string.
		bytes, err = json.Marshal(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}
		managedSystemJson = string(bytes)
	}

	path := fmt.Sprintf("/Workgroups/%s/ManagedSystems", workGroupId)
	managedSystemResponse, err = ManagedSystemObj.createManagedSystem(constants.CreateManagedSystemByWorkGroupId, path, managedSystemJson)

	if err != nil {
		return managedSystemResponse, err
	}

	return managedSystemResponse, nil

}

// CreateManagedSystemByDataBaseIdFlow is responsible for creating managed_systems by Database Id in Password Safe.
func (ManagedSystemObj *ManagedSystemObj) CreateManagedSystemByDataBaseIdFlow(workGroupId string, managedSystemDetailsInterface interface{}) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate
	var managedSystemJson string
	var err error

	if workGroupId == "" {
		return managedSystemResponse, errors.New("database Id is empty, please send a valid Database Id")
	}

	// just one payload
	managedSystemDetails, ok := managedSystemDetailsInterface.(entities.ManagedSystemsByDatabaseIdDetailsBaseConfig)
	if ok {
		err = utils.ValidateData(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}

		var bytes []byte

		// Convert object to json string.
		bytes, err = json.Marshal(managedSystemDetails)
		if err != nil {
			return managedSystemResponse, err
		}
		managedSystemJson = string(bytes)
	}

	path := fmt.Sprintf("/Databases/%s/ManagedSystems", workGroupId)
	managedSystemResponse, err = ManagedSystemObj.createManagedSystem(constants.CreateManagedSystemByDataBaseId, path, managedSystemJson)

	if err != nil {
		return managedSystemResponse, err
	}

	return managedSystemResponse, nil

}

// createManagedSystem calls Password Safe API enpoint to create managed_systems.
func (ManagedSystemObj *ManagedSystemObj) createManagedSystem(method string, path string, payload string) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate

	b := bytes.NewBufferString(payload)

	createManagedSystemUrl := ManagedSystemObj.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", "POST", createManagedSystemUrl)
	ManagedSystemObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createManagedSystemUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  ManagedSystemObj.authenticationObj.ApiVersion,
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = ManagedSystemObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, ManagedSystemObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.ManagedSystemResponseCreate{}, technicalError
	}

	if businessError != nil {
		return entities.ManagedSystemResponseCreate{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.ManagedSystemResponseCreate{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &managedSystemResponse)

	if err != nil {
		ManagedSystemObj.log.Error(err.Error())
		return entities.ManagedSystemResponseCreate{}, err
	}

	return managedSystemResponse, nil

}

// GetManagedSystemsListFlow get managed system list.
func (ManagedSystemObj *ManagedSystemObj) GetManagedSystemsListFlow() ([]entities.ManagedSystemResponseCreate, error) {
	return ManagedSystemObj.GetManagedSystemsList("ManagedSystems", constants.GetManagedSystemsList)
}

// GetManagedSystemsList call ManagedSystems enpoint
// and returns managed system list
func (ManagedSystemObj *ManagedSystemObj) GetManagedSystemsList(endpointPath string, method string) ([]entities.ManagedSystemResponseCreate, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	ManagedSystemObj.log.Debug(messageLog + endpointPath)

	url := ManagedSystemObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var managedSystemsList []entities.ManagedSystemResponseCreate

	response, err := ManagedSystemObj.authenticationObj.HttpClient.GetGeneralList(url, ManagedSystemObj.authenticationObj.ApiVersion, method, ManagedSystemObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		return managedSystemsList, err
	}

	err = json.Unmarshal(response, &managedSystemsList)

	if err != nil {
		return managedSystemsList, err
	}

	if len(managedSystemsList) == 0 {
		return managedSystemsList, fmt.Errorf("empty managed systems list")
	}

	return managedSystemsList, nil

}
