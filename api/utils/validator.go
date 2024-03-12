// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"

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
	MaxFileSecretSizeBytes int    `validate:"gte=1,lte=5000000"`
}

var validate *validator.Validate

// ValidateInputs is responsible for validating end-user inputs.
func ValidateInputs(clientId string, clientSecret string, apiUrl *string, clientTimeOutinSeconds int, separator *string, verifyCa bool, logger logging.Logger, certificate string, certificate_key string, retryMaxElapsedTimeMinutes *int, maxFileSecretSizeBytes *int) error {

	if clientTimeOutinSeconds == 0 {
		clientTimeOutinSeconds = 30
	}

	if *retryMaxElapsedTimeMinutes == 0 {
		*retryMaxElapsedTimeMinutes = 2
	}

	if *maxFileSecretSizeBytes == 0 {
		*maxFileSecretSizeBytes = 4000000
	}

	if strings.TrimSpace(*separator) == "" {
		*separator = "/"
	}

	*apiUrl = strings.TrimSpace(*apiUrl)

	err := ValidateURL(*apiUrl)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	validate = validator.New(validator.WithRequiredStructEnabled())

	userInput := &UserInputValidaton{
		ClientId:               clientId,
		ClientSecret:           clientSecret,
		ApiUrl:                 *apiUrl,
		ClientTimeOutinSeconds: clientTimeOutinSeconds,
		Separator:              *separator,
		VerifyCa:               verifyCa,
		MaxFileSecretSizeBytes: *maxFileSecretSizeBytes,
	}

	if !verifyCa {
		logger.Warn("verifyCa=false is insecure, instructs not to verify the certificate authority.")
	}

	err = validate.Struct(userInput)
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

	message = fmt.Sprintf("Library settings: ClientId=%v, ApiUrl=%v, ClientTimeOutinSeconds=%v, Separator=%v, VerifyCa=%v, MaxFileSecretSizeBytes=%v, UsingCertificate=%v", userInput.ClientId, userInput.ApiUrl, userInput.ClientTimeOutinSeconds, userInput.Separator, userInput.VerifyCa, userInput.MaxFileSecretSizeBytes, certificate != "")
	logger.Debug(message)
	return nil
}

// This method is responsbile for validating that the paths and names are valid.
func ValidatePaths(secretPaths []string, isManagedAccount bool, separator string, logger logging.Logger) []string {

	newSecretPaths := []string{}

	var maxAccountNameLength = 245
	var maxSystemNameLength = 128
	var maxPathLength = 1792
	var maxTitleLength = 256

	for _, secretToRetrieve := range secretPaths {

		// validate empty paths
		if strings.TrimSpace(secretToRetrieve) == "" {
			logger.Error("Empty path encountered. Validate your path input.")
			continue
		}

		maxPath := maxPathLength
		maxName := maxTitleLength
		invalidPathName := "path"
		invalidName := "title"
		maxPathDepth := 7
		titleDepth := 1

		if isManagedAccount {
			maxPath = maxSystemNameLength
			maxName = maxAccountNameLength
			invalidPathName = "system name"
			invalidName = "account name"
			maxPathDepth = 1
		}

		retrievalData := strings.Split(secretToRetrieve, separator)

		// validate max depth
		if len(retrievalData) > maxPathDepth+titleDepth {
			message := fmt.Sprintf("Invalid %s PathDepth=%v, valid path depth is %v, this secret will be skipped.", invalidPathName, len(retrievalData)-titleDepth, maxPathDepth)
			logger.Error(message)
			continue
		}

		name := retrievalData[len(retrievalData)-1]
		path := retrievalData[0]
		if len(retrievalData) > 2 {
			retrievalData[len(retrievalData)-1] = ""
			path = strings.TrimSuffix(strings.Join(retrievalData, separator), separator)
		}

		// trim all the leading and trailing white space
		path = strings.TrimSpace(path)
		name = strings.TrimSpace(name)

		// validate max path and name length
		if len(path) > maxPath || path == "" {
			message := fmt.Sprintf("Invalid %s length=%v, valid length between 1 and %v, this secret will be skipped.", invalidPathName, len(path), maxName)
			logger.Error(message)
			continue
		} else if len(name) > maxName || name == "" {
			message := fmt.Sprintf("%s=%s but found invalid %s length=%v, valid length between 1 and %v, this secret will be skipped.", invalidPathName, path, invalidName, len(name), maxName)
			logger.Error(message)
			continue
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
	if scheme != "https" {
		message := fmt.Sprintf("%s is not support. Use https", scheme)
		return errors.New(message)
	}

	if !strings.Contains(val.Path, "/BeyondTrust/api/public/v") {
		message := "invalid API URL, it must contains /BeyondTrust/api/public/v as part of the path"
		return errors.New(message)
	}

	return nil
}
