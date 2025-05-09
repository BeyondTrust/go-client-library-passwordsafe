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
	ApiKey                     string
	ClientID                   string
	ClientSecret               string
	ApiUrl                     *string
	ApiVersion                 string
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
	ApiKey                 string `validate:"omitempty,min=128,max=263"`
	ClientId               string `validate:"omitempty,min=36,max=36,required_without=ApiKey"`
	ClientSecret           string `validate:"omitempty,min=36,max=64,required_without=ApiKey"`
	ApiVersion             string `validate:"omitempty,min=3,max=3"`
	ApiUrl                 string `validate:"required,http_url"`
	ClientTimeOutinSeconds int    `validate:"gte=1,lte=300"`
	Separator              string `validate:"omitempty,required,min=1,max=1"`
	MaxFileSecretSizeBytes int    `validate:"omitempty,gte=1,lte=5000000"`
}

// ValidateCertificateInfo validate certificate data.
func ValidateCertificateInfo(params ValidationParams) error {
	message := ""
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

	return nil
}

// ValidateInputs is responsible for validating end-user inputs.
func ValidateInputs(params ValidationParams) error {

	if params.ClientTimeOutInSeconds == 0 {
		params.ClientTimeOutInSeconds = 30
	}

	if *params.RetryMaxElapsedTimeMinutes == 0 {
		*params.RetryMaxElapsedTimeMinutes = 2
	}

	*params.ApiUrl = strings.TrimSpace(*params.ApiUrl)

	err := ValidateURL(*params.ApiUrl)
	if err != nil {
		params.Logger.Error(err.Error())
		return err
	}

	userInput := &UserInputValidaton{
		ApiKey:                 params.ApiKey,
		ClientId:               params.ClientID,
		ClientSecret:           params.ClientSecret,
		ApiUrl:                 *params.ApiUrl,
		ApiVersion:             params.ApiVersion,
		ClientTimeOutinSeconds: params.ClientTimeOutInSeconds,
	}

	if !params.VerifyCa {
		params.Logger.Warn("verifyCa=false is insecure, instructs not to verify the certificate authority.")
	}

	err = ValidateData(userInput)
	if err != nil {
		params.Logger.Error(err.Error())
		return err
	}

	message := ""

	if params.Certificate != "" && params.CertificateKey != "" {
		err = ValidateCertificateInfo(params)
		if err != nil {
			return err
		}
	}

	message = fmt.Sprintf("Library settings: ClientId=%v, ApiUrl=%v, ClientTimeOutinSeconds=%v, VerifyCa=%v, UsingCertificate=%v", userInput.ClientId, userInput.ApiUrl, userInput.ClientTimeOutinSeconds, params.VerifyCa, params.Certificate != "")
	params.Logger.Debug(message)
	return nil
}

// ValidateSinglePath responsbile for validating that one path and one name are valid.
func ValidateSinglePath(maxPath int, maxName int, invalidPathName string, invalidName string, maxPathDepth int, retrievalData []string, separator string) (string, error) {

	titleDepth := 1
	// validate max depth
	if len(retrievalData) > maxPathDepth+titleDepth {
		return "", fmt.Errorf("invalid %s PathDepth=%v, valid path depth is %v, this secret will be skipped", invalidPathName, len(retrievalData)-titleDepth, maxPathDepth)
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
		return "", fmt.Errorf("invalid %s length=%v, valid length between 1 and %v, this secret will be skipped", invalidPathName, len(path), maxName)

	} else if len(name) > maxName || name == "" {
		return "", fmt.Errorf("%s=%s but found invalid %s length=%v, valid length between 1 and %v, this secret will be skipped", invalidPathName, path, invalidName, len(name), maxName)
	} else {
		secretPath := fmt.Sprintf("%s%s%s", path, separator, name)
		return secretPath, nil
	}
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

		if isManagedAccount {
			maxPath = maxSystemNameLength
			maxName = maxAccountNameLength
			invalidPathName = "system name"
			invalidName = "account name"
			maxPathDepth = 1
		}

		retrievalData := strings.Split(secretToRetrieve, separator)

		newSecretPath, err := ValidateSinglePath(maxPath, maxName, invalidPathName, invalidName, maxPathDepth, retrievalData, separator)
		if err != nil {
			logger.Error(err.Error())
			return newSecretPaths
		}

		newSecretPaths = append(newSecretPaths, newSecretPath)
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

// ValidateCreateManagedAccountInput responsible for validating Managed Account input
func ValidateCreateManagedAccountInput(accountDetails entities.AccountDetails) (entities.AccountDetails, error) {
	validate := validator.New()
	err := validate.Struct(accountDetails)

	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			return accountDetails, errors.New(FormatErrorMessage(err))
		}
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

// ValidateInputs responsible for validating objects Details (WorkGroupDetails, FolderDetails, SecretTextDetails...)
func ValidateData(objDetails interface{}) error {
	validate := validator.New()
	err := validate.Struct(objDetails)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			return errors.New(FormatErrorMessage(err))
		}
	}
	return nil
}

// FormatErrorMessage responsible for formating errors text.
func FormatErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("The field '%s' is required.", err.Field())
	case "required_if":
		return fmt.Sprintf("Field '%s' is mandatory when %s", err.Field(), err.Param())
	case "oneof":
		return fmt.Sprintf("The field '%s' must be one of the following values: %s.", err.Field(), err.Param())
	case "required_without":
		return fmt.Sprintf("The field '%s' is required when the field '%s' is not provided.", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("Max length '%s' for '%s' field.", err.Param(), err.Field())
	case "ip":
		return fmt.Sprintf("Bad IP value: '%s' in '%s' field", err.Value(), err.Field())
	default:
		return fmt.Sprintf("Error in field %s : %s / %s.", err.Field(), err.Tag(), err.Param())
	}
}
