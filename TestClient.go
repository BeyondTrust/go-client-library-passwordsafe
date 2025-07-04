// This script is intended for testing purposes (go client library client) only and is not part of the project.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/assets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/databases"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/functional_accounts"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	managed_accounts "github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_account"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_systems"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/platforms"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/secrets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/workgroups"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var separator = "/"
var maxFileSecretSizeBytes = 5000000

// identifer is used to create unique objects names in payloads.
var identifier = uuid.New().String()

// call endponits from Secrets Safe API.
func callSecretSafeAPIEndpoints(authenticate *authentication.AuthenticationObj, zapLogger *logging.ZapLogger, userObject entities.SignAppinResponse) error {
	err := CreateSecretsAndFolders(authenticate, zapLogger, userObject, maxFileSecretSizeBytes)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	return nil
}

// call endponits from Password Safe API.
func callPasswordSafeAPIEndpoints(authenticate *authentication.AuthenticationObj, zapLogger *logging.ZapLogger, userObject entities.SignAppinResponse) error {
	err := GetSecretAndManagedAccount(authenticate, zapLogger, userObject, separator, maxFileSecretSizeBytes)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = CreateManagedAccount(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = CreateManagedSystem(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	return nil
}

// call endponits from Beyondinsight API.
func callBeyondInsightAPIEnpoints(authenticate *authentication.AuthenticationObj, zapLogger *logging.ZapLogger, userObject entities.SignAppinResponse) error {
	err := CreateWorkGroupFlow(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = CreateAssetWorkFlow(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = CreateDatabaseFlow(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = CreateFunctionalAccountWorkFlow(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	err = GetFunctionalAccountWorkFlow(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	return nil

}

// main funtion
func main() {

	// create a zap logger
	//logger, _ := zap.NewProduction()
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	// the recommended version is 3.1. If no version is specified,
	// the default API version 3.0 will be used
	apiVersion := "3.1"
	apiUrl := os.Getenv("PASSWORD_SAFE_API_URL")
	clientId := os.Getenv("PASSWORD_SAFE_CLIENT_ID")
	clientSecret := os.Getenv("PASSWORD_SAFE_CLIENT_SECRET")

	// Set when client certificate is required and pfx file was decrypted before.
	certificate := os.Getenv("PASSWORD_SAFE_CERTIFICATE")
	certificateKey := os.Getenv("PASSWORD_SAFE_CERTIFICATE_KEY")

	// Set when client certificate is required and it has not been decrypted.
	certificatePath := os.Getenv("PASSWORD_SAFE_CERTIFICATE_PATH")
	certificateName := os.Getenv("PASSWORD_SAFE_CERTIFICATE_NAME")
	certificatePassword := os.Getenv("PASSWORD_SAFE_CERTIFICATE_PASSWORD")

	clientTimeOutInSeconds := 30
	verifyCa := true
	retryMaxElapsedTimeMinutes := 2

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(retryMaxElapsedTimeMinutes) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	// Create an instance of ValidationParams
	params := utils.ValidationParams{
		ClientID:                   clientId,
		ClientSecret:               clientSecret,
		ApiUrl:                     &apiUrl,
		ApiVersion:                 apiVersion,
		ClientTimeOutInSeconds:     clientTimeOutInSeconds,
		VerifyCa:                   verifyCa,
		Logger:                     zapLogger,
		Certificate:                certificate,
		CertificateKey:             certificateKey,
		RetryMaxElapsedTimeMinutes: &retryMaxElapsedTimeMinutes,
	}

	var err error

	// validate inputs
	errorsInInputs := utils.ValidateInputs(params)

	if errorsInInputs != nil {
		zapLogger.Error(fmt.Sprintf("Error: %v", errorsInInputs))
		return
	}

	certificate, certificateKey, _ = GetCertificateData(certificatePath, certificateName, certificatePassword, zapLogger)

	// creating a http client
	httpClientObj, _ := utils.GetHttpClient(clientTimeOutInSeconds, verifyCa, certificate, certificateKey, zapLogger)

	authParams := authentication.AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                apiUrl,
		APIVersion:                 apiVersion,
		ClientID:                   clientId,
		ClientSecret:               clientSecret,
		ApiKey:                     "fakeone_a654+9sdf7+8we4f",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 30,
	}

	// instantiating authenticate obj
	authenticate, _ := authentication.Authenticate(authParams)

	// authenticating
	userObject, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// call API's

	err = callSecretSafeAPIEndpoints(authenticate, zapLogger, userObject)
	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	err = callBeyondInsightAPIEnpoints(authenticate, zapLogger, userObject)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	err = callPasswordSafeAPIEndpoints(authenticate, zapLogger, userObject)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	// call all get list methods.
	err = CallGetListMethods(authenticate, zapLogger)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	err = CreateManagedSystem(authenticate, zapLogger)
	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	// signing out
	err = authenticate.SignOut()

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	zapLogger.Debug(fmt.Sprintf("Signed out user: %v", userObject.UserName))

}

func GetCertificateData(certificatePath string, certificateName string, certificatePassword string, zapLogger *logging.ZapLogger) (string, string, error) {

	if certificateName != "" {
		// Decrypt pfx certificate when certificate is not empty to get certificate and certificate key values.
		certificate, certificateKey, err := utils.GetPFXContent(certificatePath, certificateName, certificatePassword, zapLogger)
		if err != nil {
			zapLogger.Error(err.Error())
			return os.Getenv("PASSWORD_SAFE_CERTIFICATE"), os.Getenv("PASSWORD_SAFE_CERTIFICATE_KEY"), err
		}
		return certificate, certificateKey, nil

	}
	// Return certificate and certificate key values from env vars.
	return os.Getenv("PASSWORD_SAFE_CERTIFICATE"), os.Getenv("PASSWORD_SAFE_CERTIFICATE_KEY"), nil
}

// GetSecretAndManagedAccount test method to get managed accounts from PS API.
func GetSecretAndManagedAccount(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger, userObject entities.SignAppinResponse, separator string, maxFileSecretSizeBytes int) error {

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticationObj, zapLogger, maxFileSecretSizeBytes)

	secretPaths := []string{"oauthgrp/credential8", "oauthgrp/file1"}

	gotSecrets, _ := secretObj.GetSecrets(secretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotSecrets))

	// getting single secret
	gotSecret, _ := secretObj.GetSecret("oauthgrp/credential8", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("Secret Test: %v", gotSecret))

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticationObj, zapLogger)

	newSecretPaths := []string{"system01/managed_account01", "system01/managed_account02"}

	//managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(newSecretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	gotManagedAccount, _ := manageAccountObj.GetSecret("system01/managed_account01", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("Managed Account Test: %v", gotManagedAccount))

	return nil
}

// CreateManagedAccount test method to create managed accounts in PS API.
func CreateManagedAccount(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticationObj, zapLogger)

	account := entities.AccountDetails{
		AccountName:                       "ManagedAccountTest_" + identifier,
		Password:                          constants.FakePassword,
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
		MaxReleaseDuration:                300000,
		ISAReleaseDuration:                180,
		MaxConcurrentRequests:             5,
		AutoManagementFlag:                false,
		DSSAutoManagementFlag:             false,
		CheckPasswordFlag:                 true,
		ResetPasswordOnMismatchFlag:       false,
		ChangePasswordAfterAnyReleaseFlag: true,
		ChangeFrequencyDays:               1,
		ChangeTime:                        "22:25",
		NextChangeDate:                    "2023-12-01",
		UseOwnCredentials:                 true,
		ChangeWindowsAutoLogonFlag:        true,
		ChangeComPlusFlag:                 false,
		ObjectID:                          "uniqueObjectID",
	}

	// creating a managed account in system_integration_test managed system.
	createResponse, err := manageAccountObj.ManageAccountCreateFlow("system_integration_test", account)

	if err != nil {
		zapLogger.Error(fmt.Sprintf(" %v", err))
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("Created Managed Account: %v", createResponse.AccountName))

	return nil
}

// CreateSecretsAndFolders test method to create secrets/folders/safes in PS API.
func CreateSecretsAndFolders(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger, userObject entities.SignAppinResponse, maxFileSecretSizeBytes int) error {

	secretObj, _ := secrets.NewSecretObj(*authenticationObj, zapLogger, maxFileSecretSizeBytes)

	secretDetailsConfig := entities.SecretDetailsBaseConfig{
		Title:       "CREDENTIAL_" + identifier,
		Description: "My Credential Secret Description",
		Notes:       "My note",
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	objCredential := entities.SecretCredentialDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Username:                "my_user",
		Password:                constants.FakePassword,

		Owners: []entities.OwnerDetailsGroupId{
			{
				GroupId: 1,
				UserId:  userObject.UserId,
				Name:    userObject.UserName,
				Email:   userObject.EmailAddress,
			},
		},
	}

	// creating a credential secret in folder1.
	createdSecret, err := secretObj.CreateSecretFlow("folder1", objCredential)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Credential secret: %v", createdSecret.Title))

	secretDetailsConfig = entities.SecretDetailsBaseConfig{
		Title:       "TEXT_" + identifier,
		Description: "My Text Secret Description",
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	objText := entities.SecretTextDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Text:                    constants.FakePassword,
		FolderId:                uuid.New(),
		Owners: []entities.OwnerDetailsGroupId{
			{
				UserId: userObject.UserId,
				Name:   userObject.UserName,
				Email:  userObject.EmailAddress,
			},
		},
	}

	// creating a text secret in folder1.
	createdSecret, err = secretObj.CreateSecretFlow("folder1", objText)

	if err != nil {
		zapLogger.Error(err.Error())
		return nil
	}
	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Text secret: %v", createdSecret.Title))

	// just for test purposes, file test_secret.txt should not be present in repo.
	fileContent, err := os.ReadFile("test_secret.txt")
	if err != nil {
		zapLogger.Error(err.Error())
		return nil
	}

	secretDetailsConfig = entities.SecretDetailsBaseConfig{
		Title:       "FILE_" + identifier,
		Description: "My File Secret Description",
		Notes:       "Notes 1",
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	objFile := entities.SecretFileDetailsConfig31{
		SecretDetailsBaseConfig: secretDetailsConfig,
		Owners: []entities.OwnerDetailsGroupId{
			{
				UserId: userObject.UserId,
				Name:   userObject.UserName,
				Email:  userObject.EmailAddress,
			},
		},

		FileName:    "my_secret.txt",
		FileContent: string(fileContent),
	}

	// creating a file secret in folder1.
	createdSecret, err = secretObj.CreateSecretFlow("folder1", objFile)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created File secret: %v", createdSecret.Title))

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + identifier,
		Description: "My Folder Secret Description",
	}

	// creating a folder secret in folder1 folder.
	createdFolder, err := secretObj.CreateFolderFlow("folder1", folderDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Folder: %v", createdFolder.Name))

	safeDetails := entities.FolderDetails{
		Name:        "SAFE_" + identifier,
		Description: "My new Safe",
		FolderType:  "SAFE",
	}

	// creating a safe.
	createdSafe, err := secretObj.CreateFolderFlow("", safeDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Safe: %v", createdSafe.Name))

	return nil
}

// CreateWorkGroupFlow test method to create workgroups in PS API.
func CreateWorkGroupFlow(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating workgroup obj
	workGroupObj, _ := workgroups.NewWorkGroupObj(*authenticationObj, zapLogger)

	workGroupDetails := entities.WorkGroupDetails{
		Name: "WORKGROUP_" + identifier,
	}

	// creating a workgroup.
	createdWorkGroup, err := workGroupObj.CreateWorkGroupFlow(workGroupDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Workgroup: %v", createdWorkGroup.ID))

	return nil
}

// CreateAssetWorkFlow test method to create assets in PS API.
func CreateAssetWorkFlow(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating asset obj
	assetObj, _ := assets.NewAssetObj(*authenticationObj, zapLogger)

	assetDetails := entities.AssetDetails{
		IPAddress:       "192.16.1.1",
		AssetName:       "ASSET_" + identifier,
		DnsName:         "workstation01.local",
		DomainName:      "example.com",
		MacAddress:      "00:1A:2B:3C:4D:5E",
		AssetType:       "Laptop",
		Description:     "Asset Description",
		OperatingSystem: "Windows 11",
	}

	// creating an asset by workgroup id
	createdAsset, err := assetObj.CreateAssetByworkgroupIDFlow("6", assetDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Asset by workgroup id: %v", createdAsset.AssetName))

	// creating an asset by workgroup name
	createdAsset, err = assetObj.CreateAssetByWorkGroupNameFlow("test", assetDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Asset by workgroup name: %v", createdAsset.AssetName))

	return nil
}

// CreateDatabaseFlow test method to create databases in PS API.
func CreateDatabaseFlow(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating database obj
	databaseObj, _ := databases.NewDatabaseObj(*authenticationObj, zapLogger)

	databaseDetails := entities.DatabaseDetails{
		PlatformID:        9,
		InstanceName:      "DATABASE_" + identifier,
		IsDefaultInstance: true,
		Port:              5432,
		Version:           "15.2",
		Template:          "StandardTemplate",
	}

	// creating a database by asset
	createdDatabase, err := databaseObj.CreateDatabaseFlow("28", databaseDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Database by Asset: %v", createdDatabase))

	return nil
}

// CreateManagedSystem test method to create managed systems in PS API.
func CreateManagedSystem(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating managed system obj
	managedSystemObj, _ := managed_systems.NewManagedSystem(*authenticationObj, zapLogger)

	// creating a managed system using Asset Id
	managedSystemByAssetDetails := entities.ManagedSystemsByAssetIdDetailsConfig30{
		ManagedSystemsByAssetIdDetailsBaseConfig: entities.ManagedSystemsByAssetIdDetailsBaseConfig{

			PlatformID:                        2,
			ContactEmail:                      "admin@example.com",
			Description:                       "Main Managed System",
			Port:                              8080,
			Timeout:                           50,
			SshKeyEnforcementMode:             1,
			PasswordRuleID:                    0,
			DSSKeyRuleID:                      0,
			LoginAccountID:                    0,
			ReleaseDuration:                   60,
			MaxReleaseDuration:                120,
			ISAReleaseDuration:                30,
			AutoManagementFlag:                false,
			FunctionalAccountID:               20,
			ElevationCommand:                  "sudo su",
			CheckPasswordFlag:                 true,
			ChangePasswordAfterAnyReleaseFlag: false,
			ResetPasswordOnMismatchFlag:       true,
			ChangeFrequencyType:               "first",
			ChangeFrequencyDays:               7,
			ChangeTime:                        "23:00",
		},
	}

	// creating a managed system by asset
	createdManagedSystem, err := managedSystemObj.CreateManagedSystemByAssetIdFlow("1", managedSystemByAssetDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Managed System by Asset: %v", createdManagedSystem))

	// creating a managed system by workgroup Id
	managedSystemByWorkGroupDetails := entities.ManagedSystemsByWorkGroupIdDetailsConfig30{
		ManagedSystemsByWorkGroupIdDetailsBaseConfig: entities.ManagedSystemsByWorkGroupIdDetailsBaseConfig{
			EntityTypeID:                       1,
			HostName:                           "example.com",
			IPAddress:                          "192.168.1.1",
			DnsName:                            "example.local",
			InstanceName:                       "Instance1",
			IsDefaultInstance:                  true,
			Template:                           "DefaultTemplate",
			ForestName:                         "exampleForest",
			UseSSL:                             false,
			PlatformID:                         2,
			NetBiosName:                        "EXAMPLE",
			ContactEmail:                       "admin@example.com",
			Description:                        "Example system",
			Port:                               443,
			Timeout:                            30,
			SshKeyEnforcementMode:              1,
			PasswordRuleID:                     0,
			DSSKeyRuleID:                       0,
			LoginAccountID:                     0,
			AccountNameFormat:                  1,
			OracleInternetDirectoryID:          identifier,
			OracleInternetDirectoryServiceName: "OracleService",
			ReleaseDuration:                    60,
			MaxReleaseDuration:                 120,
			ISAReleaseDuration:                 180,
			AutoManagementFlag:                 false,
			FunctionalAccountID:                0,
			ElevationCommand:                   "sudo su",
			CheckPasswordFlag:                  true,
			ChangePasswordAfterAnyReleaseFlag:  true,
			ResetPasswordOnMismatchFlag:        false,
			ChangeFrequencyType:                "first",
			ChangeFrequencyDays:                7,
			ChangeTime:                         "02:00",
			AccessURL:                          "https://example.com",
		},
	}

	// creating a managed system by workgroup Id
	createdManagedSystem, err = managedSystemObj.CreateManagedSystemByWorkGroupIdFlow("55", managedSystemByWorkGroupDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Managed System by Workgroup: %v", createdManagedSystem))

	// creating a managed system by database Id
	managedSystemByDatabaseDetails := entities.ManagedSystemsByDatabaseIdDetailsBaseConfig{
		ContactEmail:                      "admin@example.com",
		Description:                       "Base config for managed system by DB ID",
		Timeout:                           30,
		PasswordRuleID:                    0,
		ReleaseDuration:                   120,
		MaxReleaseDuration:                525600,
		ISAReleaseDuration:                120,
		AutoManagementFlag:                false,
		FunctionalAccountID:               0,
		CheckPasswordFlag:                 true,
		ChangePasswordAfterAnyReleaseFlag: false,
		ResetPasswordOnMismatchFlag:       true,
		ChangeFrequencyType:               "xdays",
		ChangeFrequencyDays:               30,
		ChangeTime:                        "23:30",
	}

	// creating a managed system by database Id
	createdManagedSystem, err = managedSystemObj.CreateManagedSystemByDataBaseIdFlow("55", managedSystemByDatabaseDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Managed System by Database: %v", createdManagedSystem))

	return nil
}

// CreateFunctionalAccountWorkFlow test method to create functional accounts in PS API.
func CreateFunctionalAccountWorkFlow(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating asset obj
	functionalAccountObj, _ := functional_accounts.NewFuncionalAccount(*authenticationObj, zapLogger)

	functionalAccountDetails := entities.FunctionalAccountDetails{
		PlatformID:          1,
		DomainName:          "corp.example.com",
		AccountName:         "svc-monitoring",
		DisplayName:         "FUNCTIONAL_ACCOUNT" + identifier,
		Password:            constants.FakePassword,
		PrivateKey:          "private key value",
		Passphrase:          "my-passphrase",
		Description:         "Used for monitoring agents to access the platform",
		ElevationCommand:    "sudo",
		TenantID:            "123e4567-e89b-12d3-a456-426614174000",
		ObjectID:            "abc12345-def6-7890-gh12-ijklmnopqrst",
		Secret:              "super-secret-value",
		ServiceAccountEmail: "monitoring@project.iam.gserviceaccount.com",
		AzureInstance:       "AzurePublic",
	}

	// creating a functional account
	createdFunctionalAccount, err := functionalAccountObj.CreateFunctionalAccountFlow(functionalAccountDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Functional Account: %v", createdFunctionalAccount.AccountName))

	return nil
}

// GetFunctionalAccountWorkFlow test method to get functional accounts list from PS API.
func GetFunctionalAccountWorkFlow(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {
	// instantiating asset obj
	functionalAccountObj, _ := functional_accounts.NewFuncionalAccount(*authenticationObj, zapLogger)

	// getting a functional account
	functionalAccountsList, err := functionalAccountObj.GetFunctionalAccountsFlow()

	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Functional AccountS List: %v", functionalAccountsList))

	return nil
}

func CallGetListMethods(authenticationObj *authentication.AuthenticationObj, zapLogger *logging.ZapLogger) error {

	// managed accounts list
	managedAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticationObj, zapLogger)
	managedAccountlist, err := managedAccountObj.GetManagedAccountsListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("managed account List Lenght: %v", len(managedAccountlist)))

	// assets list
	assetObj, _ := assets.NewAssetObj(*authenticationObj, zapLogger)
	assetlist, err := assetObj.GetAssetsListByWorkgroupIdFlow("1")
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("Assets by Id List Lenght: %v", len(assetlist)))

	// workgroups list
	workgroupObj, _ := workgroups.NewWorkGroupObj(*authenticationObj, zapLogger)
	workgroupList, err := workgroupObj.GetWorkgroupListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("workgroup List Lenght: %v", len(workgroupList)))

	// databases list
	databaseObj, _ := databases.NewDatabaseObj(*authenticationObj, zapLogger)
	databasesList, err := databaseObj.GetDatabasesListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("databases List Lenght: %v", len(databasesList)))

	// functional accounts list
	funcionalAccountObj, _ := functional_accounts.NewFuncionalAccount(*authenticationObj, zapLogger)
	functionalAcocuntList, err := funcionalAccountObj.GetFunctionalAccountsFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("functional accounts List Lenght: %v", len(functionalAcocuntList)))

	// safes list
	safesObj, _ := secrets.NewSecretObj(*authenticationObj, zapLogger, 0)
	safesList, err := safesObj.SecretGetSafesListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("safes List Lenght: %v", len(safesList)))

	// folders list
	folderList, err := safesObj.SecretGetFoldersListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("folders List Lenght: %v", len(folderList)))

	// platofrms list
	platformsObj, _ := platforms.NewPlatformObj(*authenticationObj, zapLogger)
	platformsList, err := platformsObj.GetPlatformsListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("platform List Lenght: %v", len(platformsList)))

	// managed systems list
	managedSystemObj, _ := managed_systems.NewManagedSystem(*authenticationObj, zapLogger)
	managedSysystemList, err := managedSystemObj.GetManagedSystemsListFlow()
	if err != nil {
		zapLogger.Error(err.Error())
		return err
	}
	zapLogger.Debug(fmt.Sprintf("managed systems List lenght: %v", len(managedSysystemList)))

	return nil

}
