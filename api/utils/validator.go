// Copyright 2024 BeyondTrust. All rights reserved.
// Package utils implements inputs validations
package utils

import (
	"errors"
	"log"

	validator "github.com/go-playground/validator/v10"
)

type UserInputValidaton struct {
	ClientId               string `validate:"required,min=3,max=100"`
	ClientSecret           string `validate:"required,min=3,max=100"`
	ApiUrl                 string `validate:"required,http_url"`
	ClientTimeOutinSeconds int    `validate:"gte=3"`
	Separator              string `validate:"required,min=1,max=1"`
	VerifyCa               bool   `validate:"required"`
}

var validate *validator.Validate

// ValidateInputs validate inputs
func ValidateInputs(clientId string, clientSecret string, apiUrl string, clientTimeOutinSeconds int, separator string, verifyCa bool, logger *log.Logger, certificate string, certificate_key string) error {

	validate = validator.New(validator.WithRequiredStructEnabled())

	userInput := &UserInputValidaton{
		ClientId:               clientId,
		ClientSecret:           clientSecret,
		ApiUrl:                 apiUrl,
		ClientTimeOutinSeconds: clientTimeOutinSeconds,
		Separator:              separator,
		VerifyCa:               verifyCa,
	}

	err := validate.Struct(userInput)
	if err != nil {
		Logging("ERROR", err.Error(), *logger)
		return err
	}

	message := ""

	if certificate != "" && certificate_key != "" {
		if len(certificate) < 100 || len(certificate) > 4000 {
			message = "Invalid length for certificate"
			return errors.New(message)
		} else if len(certificate_key) < 100 || len(certificate_key) > 4000 {
			message = "Invalid length for certificate key"
			return errors.New(message)
		}
	}

	Logging("DEBUG", "Validation passed!", *logger)
	return nil
}
