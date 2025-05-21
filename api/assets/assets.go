// Copyright 2025 BeyondTrust. All rights reserved.
// Package assets implements functions to manage assets in Password Safe.
package assets

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

type AssetObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewAssetObj creates AssetObj
func NewAssetObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*AssetObj, error) {
	assetObj := &AssetObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return assetObj, nil
}

// createAssetFlow is responsible for creating assets in Password Safe.
func (assetObj *AssetObj) createAssetFlow(parameter string, assetDetails entities.AssetDetails) (entities.AssetResponse, error) {

	var assetResponse entities.AssetResponse

	err := utils.ValidateData(assetDetails)

	if err != nil {
		return assetResponse, err
	}

	assetResponse, err = assetObj.createAsset(parameter, assetDetails)

	if err != nil {
		return assetResponse, err
	}

	return assetResponse, nil
}

// CreateAssetByworkgroupIDFlow is responsible for creating assets using workgroup id in Password Safe.
func (assetObj *AssetObj) CreateAssetByworkgroupIDFlow(workGroupId string, assetDetails entities.AssetDetails) (entities.AssetResponse, error) {

	if workGroupId == "" {
		return entities.AssetResponse{}, errors.New("work groupId is empty, please send a valid workgroup id")
	}

	return assetObj.createAssetFlow(workGroupId, assetDetails)
}

// CreateAssetByWorkGroupNameFlow is responsible for creating assets using workgroup name in Password Safe.
func (assetObj *AssetObj) CreateAssetByWorkGroupNameFlow(workGroupName string, assetDetails entities.AssetDetails) (entities.AssetResponse, error) {

	if workGroupName == "" {
		return entities.AssetResponse{}, errors.New("workGroup name is empty, please send a valid workgroup name")
	}

	return assetObj.createAssetFlow(workGroupName, assetDetails)
}

// createAsset calls Password Safe API enpoint to create assets.
func (assetObj *AssetObj) createAsset(parameter string, assetDetails entities.AssetDetails) (entities.AssetResponse, error) {

	path := fmt.Sprintf("workgroups/%s/assets", parameter)

	assetsJson, err := json.Marshal(assetDetails)

	if err != nil {
		return entities.AssetResponse{}, err
	}

	payload := string(assetsJson)

	b := bytes.NewBufferString(payload)

	var assetResponse entities.AssetResponse

	createAssetUrl := assetObj.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", "POST", createAssetUrl)
	assetObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         createAssetUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      constants.CreateAsset,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  assetObj.authenticationObj.ApiVersion,
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = assetObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, assetObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.AssetResponse{}, technicalError
	}

	if businessError != nil {
		return entities.AssetResponse{}, businessError
	}

	defer func() { _ = body.Close() }()

	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.AssetResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &assetResponse)

	if err != nil {
		assetObj.log.Error(err.Error())
		return entities.AssetResponse{}, err
	}

	return assetResponse, nil

}

// GetAssetsListByWorkgroupIdFlow get assets list by workgroup Id.
func (platformObj *AssetObj) GetAssetsListByWorkgroupIdFlow(workgroupId string) ([]entities.AssetResponse, error) {
	path := fmt.Sprintf("workgroups/%s/assets", workgroupId)
	return platformObj.GetAssetsList(path, constants.GetAssetsListByWorkgroupId)
}

// GetAssetsListByWorkgroupNameFlow get assets list by workgroup name.
func (platformObj *AssetObj) GetAssetsListByWorkgroupNameFlow(workgroupName string) ([]entities.AssetResponse, error) {
	path := fmt.Sprintf("workgroups/%s/assets", workgroupName)
	return platformObj.GetAssetsList(path, constants.GetAssetsListByWorkgroupName)
}

// GetAssetsList call assets enpoint
// and returns assets list
func (platformObj *AssetObj) GetAssetsList(endpointPath string, method string) ([]entities.AssetResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	platformObj.log.Debug(messageLog)

	url := platformObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var assetsList []entities.AssetResponse

	response, err := platformObj.authenticationObj.HttpClient.GetGeneralList(url, platformObj.authenticationObj.ApiVersion, method, platformObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		platformObj.log.Error(err.Error())
		return assetsList, err
	}

	err = json.Unmarshal(response, &assetsList)
	if err != nil {
		platformObj.log.Error(err.Error())
		return assetsList, err
	}

	if len(assetsList) == 0 {
		return assetsList, fmt.Errorf("empty assets list")
	}

	return assetsList, nil

}
