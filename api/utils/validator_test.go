// Copyright 2024 BeyondTrust. All rights reserved.
// utils responsible for utility functions.
// Unit tests for utils package.
package utils

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestValidateDataSucessCase(t *testing.T) {

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.16.1.2",
		AssetName:       "asset_name",
		DnsName:         "workstation01.local",
		DomainName:      "example.com",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Laptop",
		Description:     "Device Description",
		OperatingSystem: "Windows 11",
	}

	// Correct data, happy path.
	err := ValidateData(assetDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateDataBadIP(t *testing.T) {

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.16.1",
		AssetName:       "asset_name",
		DnsName:         "workstation01.local",
		DomainName:      "example.com",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Laptop",
		Description:     "Asset Description",
		OperatingSystem: "Windows 11",
	}

	// Bad IP case.
	err := ValidateData(assetDetails)

	expetedErrorMessage := "Bad IP value: '192.16.1' in 'IPAddress' field"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateCreateManagedAccountInputEmptyPassword(t *testing.T) {

	accountDetails := entities.AccountDetails{
		AccountName: "ManagedAccountTest_" + uuid.New().String(),
		Password:    "",
	}

	// Empty password case.
	_, err := ValidateCreateManagedAccountInput(accountDetails)

	expetedErrorMessage := "Field 'Password' is mandatory when AutoManagementFlag false"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateCreateManagedAccountInput(t *testing.T) {

	accountDetails := entities.AccountDetails{
		AccountName:                       "ManagedAccountTest_" + uuid.New().String(),
		Password:                          "Passw0rd101!*",
		DomainName:                        "exampleDomain",
		UserPrincipalName:                 "user@example.com",
		SAMAccountName:                    "samAccount",
		DistinguishedName:                 "CN=example,CN=Users,DC=domain,DC=com",
		PrivateKey:                        "privateKey",
		Passphrase:                        "passphrase",
		PasswordFallbackFlag:              true,
		LoginAccountFlag:                  false,
		Description:                       "Sample account for testing",
		ApiEnabled:                        true,
		ReleaseNotificationEmail:          "notify@example.com",
		ChangeServicesFlag:                false,
		RestartServicesFlag:               false,
		ChangeTasksFlag:                   true,
		MaxReleaseDuration:                0,
		ISAReleaseDuration:                0,
		MaxConcurrentRequests:             5,
		AutoManagementFlag:                false,
		DSSAutoManagementFlag:             false,
		CheckPasswordFlag:                 true,
		ResetPasswordOnMismatchFlag:       false,
		ChangePasswordAfterAnyReleaseFlag: true,
		ChangeFrequencyDays:               1,
		ChangeTime:                        "",
		NextChangeDate:                    "2023-12-01",
		UseOwnCredentials:                 true,
		ChangeWindowsAutoLogonFlag:        true,
		ChangeComPlusFlag:                 false,
		ObjectID:                          "uniqueObjectID",
		ReleaseDuration:                   0,
		ChangeFrequencyType:               "",
	}

	// Correct data, happy path.
	_, err := ValidateCreateManagedAccountInput(accountDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateURL(t *testing.T) {

	// Happy path.
	err := ValidateURL(constants.FakeApiUrl)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Invalid protocol.
	err = ValidateURL("http://fakeurl:443/BeyondTrust/api/public/v3/")
	expetedErrorMessage := "http is not support. Use https"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	// Invalid path.
	err = ValidateURL("https://fakeurl:443/BeyondTrust/api/private/wrongpath/")
	expetedErrorMessage = "invalid API URL, it must contains /BeyondTrust/api/public/v as part of the path"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestValidatePaths(t *testing.T) {

	// Validate paths for secrets.
	response := ValidatePaths([]string{"path/title", "path/title2"}, false, "/", nil)

	expetedResponse := []string{"path/title", "path/title2"}

	if !reflect.DeepEqual(response, expetedResponse) {
		t.Errorf("Test case Failed %v, %v", response, expetedResponse)
	}

	// Validate paths for managed accounts.
	response = ValidatePaths([]string{"account/system1", "account/system2"}, true, "/", nil)

	expetedResponse = []string{"account/system1", "account/system2"}

	if !reflect.DeepEqual(response, expetedResponse) {
		t.Errorf("Test case Failed %v, %v", response, expetedResponse)
	}

}

func TestValidateValidateSinglePath(t *testing.T) {

	secretToRetrieve := "example_path/example_title"
	separator := "/"
	retrievalData := strings.Split(secretToRetrieve, separator)

	// Happy path.
	response, err := ValidateSinglePath(1792, 256, "path", "title", 7, retrievalData, separator)

	expetedResponse := "example_path/example_title"

	if err != nil {
		t.Errorf("Test case Failed ")
	}

	if expetedResponse != response {
		t.Errorf("Test case Failed %v, %v", response, expetedResponse)
	}

}

func TestValidateValidateSinglePathError(t *testing.T) {

	secretToRetrieve := "long_long_long_path_/long_long_secret_long_secret"
	separator := "/"
	retrievalData := strings.Split(secretToRetrieve, separator)

	// Long path case.
	_, err := ValidateSinglePath(5, 10, "path", "title", 7, retrievalData, separator)

	expetedErrorMessage := "invalid path length=20, valid length between 1 and 10, this secret will be skipped"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestValidateInputs(t *testing.T) {

	clientId := constants.FakeClientId
	clientSecret := constants.FakeClientSecret
	apiUrl := constants.FakeApiUrl
	apiVersion := constants.ApiVersion31
	clientTimeOutInSeconds := 30
	verifyCa := true
	retryMaxElapsedTimeMinutes := 5

	logger, _ := zap.NewDevelopment()

	zapLogger := logging.NewZapLogger(logger)

	params := ValidationParams{
		ClientID:                   clientId,
		ClientSecret:               clientSecret,
		ApiUrl:                     &apiUrl,
		ApiVersion:                 apiVersion,
		ClientTimeOutInSeconds:     clientTimeOutInSeconds,
		VerifyCa:                   verifyCa,
		Logger:                     zapLogger,
		Certificate:                "",
		CertificateKey:             "",
		RetryMaxElapsedTimeMinutes: &retryMaxElapsedTimeMinutes,
	}

	// Correct parameters.
	err := ValidateInputs(params)
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Wrong certificate.
	params.Certificate = "-----invalid certificate content-----END CERTIFICATE-----"
	params.CertificateKey = constants.FakecertificateKey

	err = ValidateInputs(params)
	expetedErrorMessage := "invalid certificate content, must contain BEGIN and END CERTIFICATE"
	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestValidateCertificateInfo(t *testing.T) {

	logger, _ := zap.NewDevelopment()

	zapLogger := logging.NewZapLogger(logger)

	params := ValidationParams{
		Certificate:    constants.Fakecertificate,
		CertificateKey: constants.FakecertificateKey,
		Logger:         zapLogger,
	}

	// Correct certificate info.
	err := ValidateCertificateInfo(params)
	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// Wrong certificate key.
	params.Certificate = constants.Fakecertificate
	params.CertificateKey = "-----BEGIN \n-----"

	err = ValidateCertificateInfo(params)
	expetedErrorMessage := "invalid certificate key content, must contain BEGIN and END PRIVATE KEY"
	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	// Wrong certificate, exceeds max length size.
	params.Certificate = strings.Repeat("fake_certificate_content", 1000)
	params.CertificateKey = constants.FakecertificateKey

	err = ValidateCertificateInfo(params)
	expetedErrorMessage = "invalid length for certificate, the maximum size is 32768 bits"
	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	// Wrong certificate key, exceeds max length size.
	params.Certificate = constants.Fakecertificate
	params.CertificateKey = strings.Repeat("fake_certificate_key_content", 1000)

	err = ValidateCertificateInfo(params)
	expetedErrorMessage = "invalid length for certificate key, the maximum size is 32768 bits"
	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}
