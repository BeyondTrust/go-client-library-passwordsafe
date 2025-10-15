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
