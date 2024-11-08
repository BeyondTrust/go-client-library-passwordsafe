// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"

	validator "github.com/go-playground/validator/v10"
)

type ValidationParams struct {
	ClientID                   string
	ClientSecret               string
	ApiUrl                     *string
	ClientTimeOutInSeconds     int
	Separator                  *string
	VerifyCa                   bool
	Logger                     logging.Logger
	Certificate                string
	CertificateKey             string
	RetryMaxElapsedTimeMinutes *int
	MaxFileSecretSizeBytes     *int
}

// UserInputValidaton responsible for input paramerter validation.
type UserInputValidaton struct {
	ClientId               string `validate:"required,min=36,max=36"`
	ClientSecret           string `validate:"required,min=36,max=64"`
	ApiUrl                 string `validate:"required,http_url"`
	ClientTimeOutinSeconds int    `validate:"gte=1,lte=300"`
	Separator              string `validate:"required,min=1,max=1"`
	MaxFileSecretSizeBytes int    `validate:"gte=1,lte=5000000"`
}

var validate *validator.Validate

// ValidateInputs is responsible for validating end-user inputs.
func ValidateInputs(params ValidationParams) error {

	if params.ClientTimeOutInSeconds == 0 {
		params.ClientTimeOutInSeconds = 30
	}

	if *params.RetryMaxElapsedTimeMinutes == 0 {
		*params.RetryMaxElapsedTimeMinutes = 2
	}

	if *params.MaxFileSecretSizeBytes == 0 {
		*params.MaxFileSecretSizeBytes = 4000000
	}

	if strings.TrimSpace(*params.Separator) == "" {
		*params.Separator = "/"
	}

	*params.ApiUrl = strings.TrimSpace(*params.ApiUrl)

	err := ValidateURL(*params.ApiUrl)
	if err != nil {
		params.Logger.Error(err.Error())
		return err
	}

	validate = validator.New(validator.WithRequiredStructEnabled())

	userInput := &UserInputValidaton{
		ClientId:               params.ClientID,
		ClientSecret:           params.ClientSecret,
		ApiUrl:                 *params.ApiUrl,
		ClientTimeOutinSeconds: params.ClientTimeOutInSeconds,
		Separator:              *params.Separator,
		MaxFileSecretSizeBytes: *params.MaxFileSecretSizeBytes,
	}

	if !params.VerifyCa {
		params.Logger.Warn("verifyCa=false is insecure, instructs not to verify the certificate authority.")
	}

	err = validate.Struct(userInput)
	if err != nil {
		params.Logger.Error(err.Error())
		return err
	}

	message := ""

	if params.Certificate != "" && params.CertificateKey != "" {

		certificateLengthInBits := utf8.RuneCountInString(params.Certificate) * 8

		if certificateLengthInBits > 32768 {
			message = "invalid length for certificate, the maximum size is 32768 bits"
			params.Logger.Error(message)
			return errors.New(message)
		}

		certificateKeyLengthInBits := utf8.RuneCountInString(params.CertificateKey) * 8

		if certificateKeyLengthInBits > 32768 {
			message = "invalid length for certificate key, the maximum size is 32768 bits"
			params.Logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(params.Certificate, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(params.Certificate, "-----END CERTIFICATE-----") {
			message = "invalid certificate content, must contain BEGIN and END CERTIFICATE"
			params.Logger.Error(message)
			return errors.New(message)
		}

		if !strings.HasPrefix(params.CertificateKey, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(params.CertificateKey, "-----END PRIVATE KEY-----") {
			message = "invalid certificate key content, must contain BEGIN and END PRIVATE KEY"
			params.Logger.Error(message)
			return errors.New(message)
		}

	}

	message = fmt.Sprintf("Library settings: ClientId=%v, ApiUrl=%v, ClientTimeOutinSeconds=%v, Separator=%v, VerifyCa=%v, MaxFileSecretSizeBytes=%v, UsingCertificate=%v", userInput.ClientId, userInput.ApiUrl, userInput.ClientTimeOutinSeconds, userInput.Separator, params.VerifyCa, userInput.MaxFileSecretSizeBytes, params.Certificate != "")
	params.Logger.Debug(message)
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

func ValidateCreateManagedAccountInput(accountDetails entities.AccountDetails) (entities.AccountDetails, error) {
	validate := validator.New()
	err := validate.Struct(accountDetails)

	if err != nil {
		return accountDetails, err
	}

	if accountDetails.ChangeFrequencyType == "" {
		accountDetails.ChangeFrequencyType = "first"
	}

	if accountDetails.ReleaseDuration == 0 {
		accountDetails.ReleaseDuration = 120
	}

	if accountDetails.MaxReleaseDuration == 0 {
		accountDetails.MaxReleaseDuration = 525600
	}

	if accountDetails.ISAReleaseDuration == 0 {
		accountDetails.ISAReleaseDuration = 120
	}

	if accountDetails.ChangeTime == "" {
		accountDetails.ChangeTime = "00:00"
	}

	return accountDetails, nil
}
