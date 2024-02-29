// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	"fmt"
	logging "go-client-library-passwordsafe/api/logging"
	"net/url"
	"strings"
	"unicode/utf8"

	validator "github.com/go-playground/validator/v10"
)

// UserInputValidaton responsible for input paramerter validation.
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
func ValidateInputs(clientId string, clientSecret string, apiUrl string, clientTimeOutinSeconds int, separator *string, verifyCa bool, logger logging.Logger, certificate string, certificate_key string, retryMaxElapsedTimeMinutes *int) error {

	if clientTimeOutinSeconds == 0 {
		clientTimeOutinSeconds = 30
		*retryMaxElapsedTimeMinutes = 2

	}

	if *retryMaxElapsedTimeMinutes == 0 {
		*retryMaxElapsedTimeMinutes = 2
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

	if !verifyCa {
		logger.Warn("verifyCa=false is insecure, instructs not to verify the certificate authority.")
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
			message = "invalid length for certificate, the maximum size is 32768 bits"
			logger.Error(message)
			return errors.New(message)
		}

		certificateKeyLengthInBits := utf8.RuneCountInString(certificate_key) * 8

		if certificateKeyLengthInBits > 32768 {
			message = "invalid length for certificate key, the maximum size is 32768 bits"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(certificate, "-----END CERTIFICATE-----") {
			message = "invalid certificate content, must contain BEGIN and END CERTIFICATE"
			logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(certificate_key, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(certificate_key, "-----END PRIVATE KEY-----") {
			message = "invalid certificate key content, must contain BEGIN and END PRIVATE KEY"
			logger.Error(message)
			return errors.New(message)
		}

	}

	err = ValidateURL(apiUrl)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	message = fmt.Sprintf("Library settings: ApiUrl=%v, ClientTimeOutinSeconds=%v, Separator=%v, VerifyCa=%v", userInput.ApiUrl, userInput.ClientTimeOutinSeconds, userInput.Separator, userInput.VerifyCa)
	logger.Debug(message)
	return nil
}

// This method is responsbile for validating that the paths and names are valid.
func ValidatePaths(secretPaths []string, isManagedAccount bool, separator string, logger logging.Logger) []string {

	newSecretPaths := []string{}

	var maxAccountNameLength = 246
	var maxSystemNameLength = 129
	var maxPathLength = 1792
	var maxTitleLength = 256

	for _, secretToRetrieve := range secretPaths {

		if strings.TrimSpace(secretToRetrieve) == "" {
			logger.Warn("Empty path encountered.")
			continue
		}

		secretData := strings.Split(secretToRetrieve, separator)

		path := secretData[0]
		name := secretData[1]
		maxPath := maxPathLength
		maxName := maxTitleLength
		invalidPathName := "path"
		invalidName := "title"

		if isManagedAccount {
			maxPath = maxSystemNameLength
			maxName = maxAccountNameLength
			invalidPathName = "system name"
			invalidName = "account name"
		}

		path = strings.TrimSpace(path)
		name = strings.TrimSpace(name)

		if len(path) > maxPath || path == "" {
			message := fmt.Sprintf("Invalid %s length=%v, valid length between 1 and %v, this secret will be skipped.", invalidPathName, len(path), maxName)
			logger.Warn(message)
		} else if len(name) > maxName || name == "" {
			message := fmt.Sprintf("%s=%s but found invalid %s length=%v, valid length between 1 and %v, this secret will be skipped.", invalidPathName, path, invalidName, len(name), maxName)
			logger.Warn(message)
		} else {
			secretPath := fmt.Sprintf("%s%s%s", path, separator, name)
			newSecretPaths = append(newSecretPaths, secretPath)
		}
	}

	return newSecretPaths

}

// ValidateURL responsible for validating the Password Safe API URL.
func ValidateURL(apiUrl string) error {
	val, err := url.Parse(apiUrl)
	if err != nil {
		return err
	}

	scheme := val.Scheme
	if scheme == "http" {
		message := "http is not support. Use https"
		return errors.New(message)
	}

	if !strings.Contains(apiUrl, "/BeyondTrust/api/public/v") {
		message := "invalid API URL, it must contains /BeyondTrust/api/public/v as part of the route"
		return errors.New(message)
	}

	return nil
}
