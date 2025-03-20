// Copyright 2025 BeyondTrust. All rights reserved.
// Package databases implements functions to manage databases in Password Safe.
package databases

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"

	backoff "github.com/cenkalti/backoff/v4"
)

type DatabaseObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewDatabaseObj creates DatabaseObj
func NewDatabaseObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*DatabaseObj, error) {
	databaseObj := &DatabaseObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return databaseObj, nil
}

// CreateDatabaseFlow is responsible for creating databases in Password Safe.
func (databaseObj *DatabaseObj) CreateDatabaseFlow(assetId string, databaseDetails entities.DatabaseDetails) (entities.DatabaseResponse, error) {

	var databaseResponse entities.DatabaseResponse

	if assetId == "" {
		return databaseResponse, errors.New("asset Id is empty, please send a valid asset id")
	}

	err := utils.ValidateData(databaseDetails)

	if err != nil {
		return databaseResponse, err
	}

	databaseResponse, err = databaseObj.createDatabase(assetId, databaseDetails)

	if err != nil {
		return databaseResponse, err
	}

	return databaseResponse, nil
}

// createDatabase calls Password Safe API enpoint to create databases.
func (databaseObj *DatabaseObj) createDatabase(assetId string, database entities.DatabaseDetails) (entities.DatabaseResponse, error) {

	path := "Assets/{id}/Databases"
	path = strings.Replace(path, "{id}", assetId, 1)

	method := constants.CreateDatabase

	databaseJson, err := json.Marshal(database)

	if err != nil {
		return entities.DatabaseResponse{}, err
	}

	payload := string(databaseJson)

	b := bytes.NewBufferString(payload)

	var databaseResponse entities.DatabaseResponse

	createDatabaseUrl := databaseObj.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", "POST", createDatabaseUrl)
	databaseObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createDatabaseUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = databaseObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, databaseObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.DatabaseResponse{}, technicalError
	}

	if businessError != nil {
		return entities.DatabaseResponse{}, businessError
	}

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.DatabaseResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &databaseResponse)

	if err != nil {
		databaseObj.log.Error(err.Error())
		return entities.DatabaseResponse{}, err
	}

	return databaseResponse, nil

}
