// Copyright 2024 BeyondTrust. All rights reserved.
// Package platforms implements logic to manage platforms in PS API
package platforms

import (
	"encoding/json"
	"fmt"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
)

// PlatformObj responsible for session requests.
type PlatformObj struct {
	log               logging.Logger
	authenticationObj authentication.AuthenticationObj
}

// NewPlatformObj creates platform obj.
func NewPlatformObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*PlatformObj, error) {
	platformObj := &PlatformObj{
		log:               logger,
		authenticationObj: authentication,
	}
	return platformObj, nil
}

// GetPlatformsListFlow get platforms list.
func (platformObj *PlatformObj) GetPlatformsListFlow() ([]entities.PlatformResponse, error) {
	return platformObj.GetPlatformsList("Platforms", constants.GetPlatformsList)
}

// GetPlatformsList call Platforms enpoint
// and returns platforms list
func (platformObj *PlatformObj) GetPlatformsList(endpointPath string, method string) ([]entities.PlatformResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	platformObj.log.Debug(messageLog + endpointPath)

	url := platformObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var platformsList []entities.PlatformResponse

	response, err := platformObj.authenticationObj.HttpClient.GetGeneralList(url, platformObj.authenticationObj.ApiVersion, method, platformObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		return platformsList, err
	}

	err = json.Unmarshal(response, &platformsList)

	if err != nil {
		return platformsList, err
	}

	if len(platformsList) == 0 {
		return platformsList, fmt.Errorf("empty platforms list")
	}

	return platformsList, nil

}
