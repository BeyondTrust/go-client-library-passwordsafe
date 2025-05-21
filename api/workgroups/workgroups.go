// Copyright 2025 BeyondTrust. All rights reserved.
// Package workgroups implements functions to manage workgroups in Password Safe.
package workgroups

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"

	backoff "github.com/cenkalti/backoff/v4"
)

type WorkGroupObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewWorkGroupObj creates WorkGroupObj
func NewWorkGroupObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*WorkGroupObj, error) {
	workGroupObj := &WorkGroupObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return workGroupObj, nil
}

// CreateWorkGroupFlow is responsible for creating workgroups in Password Safe.
func (workGroupObj *WorkGroupObj) CreateWorkGroupFlow(workGroupDetails entities.WorkGroupDetails) (entities.WorkGroupResponse, error) {

	var workGroupResponse entities.WorkGroupResponse

	err := utils.ValidateData(workGroupDetails)

	if err != nil {
		return workGroupResponse, err
	}

	workGroupResponse, err = workGroupObj.createWorkGroup(workGroupDetails)

	if err != nil {
		return workGroupResponse, err
	}

	return workGroupResponse, nil
}

// createWorkGroup calls Password Safe API enpoint to create workgroups.
func (workGroupObj *WorkGroupObj) createWorkGroup(workGroup entities.WorkGroupDetails) (entities.WorkGroupResponse, error) {

	path := "Workgroups"
	method := constants.CreateWorkGroup

	workGroupJson, err := json.Marshal(workGroup)

	if err != nil {
		return entities.WorkGroupResponse{}, err
	}

	payload := string(workGroupJson)
	b := bytes.NewBufferString(payload)

	var workGroupResponse entities.WorkGroupResponse

	createWorkGroupUrl := workGroupObj.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", "POST", createWorkGroupUrl)
	workGroupObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createWorkGroupUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = workGroupObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, workGroupObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.WorkGroupResponse{}, technicalError
	}

	if businessError != nil {
		return entities.WorkGroupResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.WorkGroupResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &workGroupResponse)

	if err != nil {
		workGroupObj.log.Error(err.Error())
		return entities.WorkGroupResponse{}, err
	}

	return workGroupResponse, nil

}

// GetWorkgroupListFlow get workgroup list.
func (workGroupObj *WorkGroupObj) GetWorkgroupListFlow() ([]entities.WorkGroupResponse, error) {
	return workGroupObj.GetWorkgroupList("Workgroups", constants.GetWorkGroupsList)
}

// GetWorkgroupList call Workgroups enpoint
// and returns workgroups list
func (workGroupObj *WorkGroupObj) GetWorkgroupList(endpointPath string, method string) ([]entities.WorkGroupResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	workGroupObj.log.Debug(messageLog)

	url := workGroupObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var workgroupList []entities.WorkGroupResponse

	response, err := workGroupObj.authenticationObj.HttpClient.GetGeneralList(url, workGroupObj.authenticationObj.ApiVersion, method, workGroupObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		return workgroupList, err
	}

	err = json.Unmarshal(response, &workgroupList)

	if err != nil {
		return workgroupList, err
	}

	if len(workgroupList) == 0 {
		return workgroupList, fmt.Errorf("empty workgroups list")
	}

	return workgroupList, nil

}
