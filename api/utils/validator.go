// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	logging "go-client-library-passwordsafe/api/logging"
	"strings"
	"unicode/utf8"

	validator "github.com/go-playground/validator/v10"
)

type UserInputValidaton struct {
	ClientId               string `validate:"required,min=36,max=36"`
	ClientSecret           string `validate:"required,min=36,max=64"`
	ApiUrl                 string `validate:"required,http_url"`
	ClientTimeOutinSeconds int    `validate:"gte=1,lte=301"`
	Separator              string `validate:"required,min=1,max=1"`
	VerifyCa               bool   `validate:"required"`
}

var validate *validator.Validate

// ValidateInputs validate inputs
func ValidateInputs(clientId string, clientSecret string, apiUrl string, clientTimeOutinSeconds int, separator *string, verifyCa bool, logger logging.Logger, certificate string, certificate_key string) error {

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
			message = "Invalid length for certificate"
			logger.Error(message)
			return errors.New(message)
		}

		certificateKeyLengthInBits := utf8.RuneCountInString(certificate_key) * 8

		if certificateKeyLengthInBits > 32768 {
			message = "Invalid length for certificate key"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(certificate, "-----END CERTIFICATE-----") {
			message = "Invalid certificate content"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate_key, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(certificate_key, "-----END PRIVATE KEY-----") {
			message = "Invalid certificate key content"
			logger.Error(message)
			return errors.New(message)
		}

	}

	if !strings.Contains(apiUrl, "/BeyondTrust/api/public/v3/") {
		message = "Invalid API URL, it should contains /BeyondTrust/api/public/v3/ as path"
		logger.Error(message)
		return errors.New(message)
	}

	logger.Debug("Validation passed!")
	//Logging("DEBUG", "Validation passed!", *logger)
	return nil
}

// ValidatePaths validate path
func ValidatePath(path string) error {
	message := ""
	if len(path) > 303 {
		message = "Invalid Path Lenght"
		return errors.New(message)
	}
	return nil
}
