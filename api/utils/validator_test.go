// Copyright 2024 BeyondTrust. All rights reserved.
// utils responsible for utility functions.
// Unit tests for utils package.
package utils

import (
	"reflect"
	"testing"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/google/uuid"
)

func TestValidateData(t *testing.T) {

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

	err := ValidateData(assetDetails)

	expetedErrorMessage := "Bad IP value: '192.16.1' in 'IPAddress' field"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}
	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateCreateManagedAccountInput(t *testing.T) {

	accountDetails := entities.AccountDetails{
		AccountName: "ManagedAccountTest_" + uuid.New().String(),
		Password:    "",
	}

	_, err := ValidateCreateManagedAccountInput(accountDetails)

	expetedErrorMessage := "Field 'Password' is mandatory when AutoManagementFlag false"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	if err == nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateCreateManagedAccountInputEmptyPassword(t *testing.T) {

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

	_, err := ValidateCreateManagedAccountInput(accountDetails)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

}

func TestValidateURL(t *testing.T) {

	// happy path
	err := ValidateURL(constants.FakeApiUrl)

	if err != nil {
		t.Errorf("Test case Failed: %v", err)
	}

	// invalid protocol
	err = ValidateURL("http://fakeurl:443/BeyondTrust/api/public/v3/")
	expetedErrorMessage := "http is not support. Use https"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

	// invalid path
	err = ValidateURL("https://fakeurl:443/BeyondTrust/api/private/v3/")
	expetedErrorMessage = "invalid API URL, it must contains /BeyondTrust/api/public/v as part of the path"

	if err.Error() != expetedErrorMessage {
		t.Errorf("Test case Failed %v, %v", err.Error(), expetedErrorMessage)
	}

}

func TestValidatePaths(t *testing.T) {

	// validate paths for secrets.
	response := ValidatePaths([]string{"path/title", "path/title2"}, false, "/", nil)

	expetedResponse := []string{"path/title", "path/title2"}

	if !reflect.DeepEqual(response, expetedResponse) {
		t.Errorf("Test case Failed %v, %v", response, expetedResponse)
	}

	// validate paths for managed accounts.
	response = ValidatePaths([]string{"account/system1", "account/system2"}, true, "/", nil)

	expetedResponse = []string{"account/system1", "account/system2"}

	if !reflect.DeepEqual(response, expetedResponse) {
		t.Errorf("Test case Failed %v, %v", response, expetedResponse)
	}

}
