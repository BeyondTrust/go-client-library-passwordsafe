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

// createManagedSystemFlow is responsible for creating managed_systems in Password Safe.
func (ManagedSystemObj *ManagedSystemObj) CreateManagedSystemFlow(assetId string, managedSystemDetailsInterface interface{}) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate
	var managedSystemJson string
	var err error

	if assetId == "" {
		return managedSystemResponse, errors.New("asset id is empty, please send a valid asset id")
	}

	switch managedSystemDetails := managedSystemDetailsInterface.(type) {

	// validate request body according to the API Version.
	case entities.ManagedSystemsByAssetIdDetailsConfig3_0, // v3.0
		entities.ManagedSystemsByAssetIdDetailsConfig3_1, // v3.1
		entities.ManagedSystemsByAssetIdDetailsConfig3_2: // v3.2
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

	managedSystemResponse, err = ManagedSystemObj.createManagedSystem(assetId, managedSystemJson)

	if err != nil {
		return managedSystemResponse, err
	}

	return managedSystemResponse, nil

}

// createManagedSystem calls Password Safe API enpoint to create managed_systems.
func (ManagedSystemObj *ManagedSystemObj) createManagedSystem(assetId string, payload string) (entities.ManagedSystemResponseCreate, error) {

	var managedSystemResponse entities.ManagedSystemResponseCreate
	path := fmt.Sprintf("/Assets/%s/ManagedSystems", assetId)

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
		Method:      constants.CreateManagedSystemByAssedId,
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

	defer body.Close()
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
