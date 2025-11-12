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
func GetOwnerDetailsOwnerIdList(data map[string]interface{}, signAppinResponse entities.SignAppinResponse) []entities.OwnerDetailsOwnerId {
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
		ownersList, ok := ownersRaw.([]interface{})
		if !ok {
			return owners
		}
		for _, ownerRaw := range ownersList {
			ownerMap, ok := ownerRaw.(map[string]interface{})
			if !ok {
				continue
			}
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


// GetOwnerDetailsGroupIdList constructs a list of owner details with group IDs from the provided data map.
func GetOwnerDetailsGroupIdList(data map[string]interface{}, groupId int, signAppinResponse entities.SignAppinResponse) []entities.OwnerDetailsGroupId {
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
		ownersList, ok := ownersRaw.([]interface{})
		if !ok {
			return owners
		}
		for _, ownerRaw := range ownersList {
			ownerMap, ok := ownerRaw.(map[string]interface{})
			if !ok {
				continue
			}
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

// GetUrlsDetailsList extracts and parses URL details from the provided data map.
func GetUrlsDetailsList(d map[string]interface{}) []entities.UrlDetails {

	urls := []entities.UrlDetails{}
	urlsRaw := d["urls"]

	if urlsRaw != nil {
		urlsList, ok := urlsRaw.([]interface{})
		if !ok {
			return urls
		}
		for _, urlRaw := range urlsList {
			urlMap, ok := urlRaw.(map[string]interface{})
			if !ok {
				continue
			}

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
	if strVal, ok := val.(string); ok {
		return strVal
	}
	return defaultValue
}

// GetIntField retrieves a numeric field from a map, returning a default value if the key does not exist.
func GetIntField(data map[string]interface{}, key string, defaultValue int) int {
	val, exists := data[key]
	if !exists {
		return defaultValue
	}
	switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
	}
	return defaultValue
}