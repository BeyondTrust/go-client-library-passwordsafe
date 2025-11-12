// Copyright 2025 BeyondTrust. All rights reserved.
// Package utils implements common utility functions
package utils

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/google/uuid"

	backoff "github.com/cenkalti/backoff/v4"
)

// validateResourceID validates a resource ID based on the specified format
func validateResourceID(resourceID string, resourceType string, validateAsUUID bool) error {
	if validateAsUUID {
		_, err := uuid.Parse(resourceID)
		if err != nil {
			return fmt.Errorf("invalid UUID format for %sID: %v", resourceType, err)
		}
	} else {
		// Validate as integer
		_, err := strconv.Atoi(resourceID)
		if err != nil {
			return fmt.Errorf("invalid integer format for %sID: %v", resourceType, err)
		}
	}
	return nil
}

// DeleteResourceByID is a reusable function for deleting resources by ID.
// It supports both UUID and integer IDs and flexible URL construction.
func DeleteResourceByID(
	resourceID string,
	resourceType string,
	methodConstant string,
	urlBuilder func(id string) string,
	validateAsUUID bool,
	httpClient *HttpClientObj,
	exponentialBackOff *backoff.ExponentialBackOff,
	logger logging.Logger,
) error {
	// Validate ID format based on requirements
	err := validateResourceID(resourceID, resourceType, validateAsUUID)
	if err != nil {
		return err
	}

	url := urlBuilder(resourceID)
	messageLog := fmt.Sprintf("%v %v", "DELETE", url)
	logger.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         url,
		HttpMethod:  "DELETE",
		Body:        bytes.Buffer{},
		Method:      methodConstant,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		_, _, technicalError, businessError = httpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, exponentialBackOff)

	if technicalError != nil {
		return technicalError
	}
	if businessError != nil {
		return businessError
	}
	return nil
}


// GetOwnerDetailsOwnerIdList get Owners details list.
func GetOwnerDetailsOwnerIdList(data map[string]interface{}, ownerType string, groupId int, signAppinResponse entities.SignAppinResponse) []entities.OwnerDetailsOwnerId {
	var owners []entities.OwnerDetailsOwnerId

	mainOwner := entities.OwnerDetailsOwnerId{
		OwnerId: signAppinResponse.UserId,
		Owner:   signAppinResponse.UserName,
		Email:   signAppinResponse.EmailAddress,
	}
	owners = append(owners, mainOwner)

	ownersRaw, ok := data["owners"]
	if !ok {
		return owners
	}

	if ownersRaw != nil {
		for _, ownerRaw := range ownersRaw.([]interface{}) {
			ownerMap := ownerRaw.(map[string]interface{})
			owner := entities.OwnerDetailsOwnerId{
				OwnerId: GetIntField(ownerMap, "owner_id", 0),
				Owner:   GetStringField(ownerMap, "owner", ""),
				Email:   GetStringField(ownerMap, "email", ""),
			}
			owners = append(owners, owner)
		}
	}

	return owners
}


// GetOwnerDetailsGroupIdList get Owners details list.
func GetOwnerDetailsGroupIdList(data map[string]interface{}, ownerType string, groupId int, signAppinResponse entities.SignAppinResponse) []entities.OwnerDetailsGroupId {
	var owners []entities.OwnerDetailsGroupId

	mainOwner := entities.OwnerDetailsGroupId{
		GroupId: groupId,
		UserId:  signAppinResponse.UserId,
		Name:    signAppinResponse.Name,
		Email:   signAppinResponse.EmailAddress,
	}
	owners = append(owners, mainOwner)

	ownersRaw, ok := data["owners"]
	if !ok {
		return owners
	}

	if ownersRaw != nil {
		for _, ownerRaw := range ownersRaw.([]interface{}) {
			ownerMap := ownerRaw.(map[string]interface{})

			owner := entities.OwnerDetailsGroupId{
				GroupId: GetIntField(ownerMap, "group_id", 0),
				UserId:  GetIntField(ownerMap, "user_id", 0),
				Name:    GetStringField(ownerMap, "name", ""),
				Email:   GetStringField(ownerMap, "email", ""),
			}
			
			owners = append(owners, owner)
		}
	}

	return owners
}

// GetUrlsDetailsList get urls details list.
func GetUrlsDetailsList(d map[string]interface{}, ownerType string, groupId int) []entities.UrlDetails {

	urls := []entities.UrlDetails{}
	urlsRaw, _ := d["urls"]

	if urlsRaw != nil {
		for _, urlRaw := range urlsRaw.([]interface{}) {
			urlMap := urlRaw.(map[string]interface{})

			id, _ := uuid.Parse(GetStringField(urlMap, "id", ""))
			credentialId, _ := uuid.Parse(GetStringField(urlMap, "credential_id", ""))

			url := entities.UrlDetails{
				Id:           id,
				CredentialId: credentialId,
				Url:          GetStringField(urlMap, "url", ""),
			}
			urls = append(urls, url)
		}
	}

	return urls
}
// GetStringField retrieves a string field from a map, returning a default value if the key does not exist.
func GetStringField(data map[string]interface{}, key string, defaultValue string) string {
	val, exists := data[key]
	if !exists {
		return defaultValue
	}
	return val.(string)
}

// GetIntField retrieves a numeric field from a map, returning a default value if the key does not exist.
func GetIntField(data map[string]interface{}, key string, defaultValue int) int {
	val, exists := data[key]
	if !exists {
		return defaultValue
	}
	switch val.(type) {
		case float64:
			return int(val.(float64))
		case int:
			return val.(int)
	}
	return defaultValue
}