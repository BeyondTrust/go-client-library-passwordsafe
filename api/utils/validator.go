// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	"fmt"
	logging "go-client-library-passwordsafe/api/logging"
	"strings"
	"unicode/utf8"

	validator "github.com/go-playground/validator/v10"
)

type UserInputValidaton struct {
	ClientId               string `validate:"required,min=36,max=36"`
	ClientSecret           string `validate:"required,min=36,max=64"`
	ApiUrl                 string `validate:"required,http_url"`
	ClientTimeOutinSeconds int    `validate:"gte=1,lte=300"`
	Separator              string `validate:"required,min=1,max=1"`
	VerifyCa               bool   `validate:"required"`
}

var validate *validator.Validate

// ValidateInputs is responsible for validating end-user inputs.
func ValidateInputs(clientId string, clientSecret string, apiUrl string, clientTimeOutinSeconds int, separator *string, verifyCa bool, logger logging.Logger, certificate string, certificate_key string) error {

	if clientTimeOutinSeconds == 0 {
		clientTimeOutinSeconds = 30
	}

	validate = validator.New(validator.WithRequiredStructEnabled())

	userInput := &UserInputValidaton{
		ClientId:               clientId,
		ClientSecret:           clientSecret,
		ApiUrl:                 apiUrl,
		ClientTimeOutinSeconds: clientTimeOutinSeconds,
		Separator:              *separator,
		VerifyCa:               verifyCa,
	}

	if strings.TrimSpace(*separator) == "" {
		*separator = "/"
	}

	err := validate.Struct(userInput)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	message := ""

	if certificate != "" && certificate_key != "" {

		certificateLengthInBits := utf8.RuneCountInString(certificate) * 8

		if certificateLengthInBits > 32768 {
			message = "Invalid length for certificate, the maximum size is 32768 bits"
			logger.Error(message)
			return errors.New(message)
		}

		certificateKeyLengthInBits := utf8.RuneCountInString(certificate_key) * 8

		if certificateKeyLengthInBits > 32768 {
			message = "Invalid length for certificate key, the maximum size is 32768 bits"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(certificate, "-----END CERTIFICATE-----") {
			message = "Invalid certificate content, must contain BEGIN and END CERTIFICATE"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate_key, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(certificate_key, "-----END PRIVATE KEY-----") {
			message = "Invalid certificate key content, must contain BEGIN and END PRIVATE KEY"
			logger.Error(message)
			return errors.New(message)
		}

	}

	if !strings.Contains(apiUrl, "/BeyondTrust/api/public/v") {
		message = "Invalid API URL, it must contains /BeyondTrust/api/public/v as part of the route"
		logger.Error(message)
		return errors.New(message)
	}

	logger.Debug("Validation passed!")
	return nil
}

// ValidatePaths is responsible for validating secret paths
func ValidatePath(path string) error {
	message := ""
	if len(path) > 303 {
		message = fmt.Sprintf("Invalid Path Length, valid paths have a maximum size of %v", 303)
		return errors.New(message)
	}
	return nil
}

// ValidatePaths validate managed accounts paths
func ValidatePaths(secretPaths []string, separator string, logger logging.Logger) ([]string, error) {

	newSecretPaths := []string{}

	for _, secretToRetrieve := range secretPaths {

		if strings.TrimSpace(secretToRetrieve) == "" {
			logger.Debug("Please use a valid path")
			continue
		}

		secretData := strings.Split(secretToRetrieve, separator)

		systemName := secretData[0]
		accountName := secretData[1]

		systemName = strings.TrimSpace(systemName)
		accountName = strings.TrimSpace(accountName)

		if systemName == "" {
			logger.Debug("Please use a valid system name value")
		} else if accountName == "" {
			logger.Debug("Please use a valid account name value")
		} else {
			secretPath := fmt.Sprintf("%s%s%s", systemName, separator, accountName)
			newSecretPaths = append(newSecretPaths, secretPath)
		}
	}

	return newSecretPaths, nil

}
