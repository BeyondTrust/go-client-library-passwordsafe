package main

import (
	"fmt"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	managed_accounts "github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_account"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/secrets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	"github.com/google/uuid"

	//"os"

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

// main funtion
func main() {

	// create a zap logger
	//logger, _ := zap.NewProduction()
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	apiUrl := "https://example.com:443/BeyondTrust/api/public/v3/"
	clientId := ""
	clientSecret := ""
	separator := "/"
	certificate := ""
	certificateKey := ""
	clientTimeOutInSeconds := 30
	verifyCa := true
	retryMaxElapsedTimeMinutes := 2
	maxFileSecretSizeBytes := 5000000

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(retryMaxElapsedTimeMinutes) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	//certificate = os.Getenv("CERTIFICATE")
	//certificateKey = os.Getenv("CERTIFICATE_KEY")

	// Create an instance of ValidationParams
	params := utils.ValidationParams{
		ClientID:                   clientId,
		ClientSecret:               clientSecret,
		ApiUrl:                     &apiUrl,
		ClientTimeOutInSeconds:     clientTimeOutInSeconds,
		Separator:                  &separator,
		VerifyCa:                   verifyCa,
		Logger:                     zapLogger,
		Certificate:                certificate,
		CertificateKey:             certificateKey,
		RetryMaxElapsedTimeMinutes: &retryMaxElapsedTimeMinutes,
		MaxFileSecretSizeBytes:     &maxFileSecretSizeBytes,
	}

	// validate inputs
	errorsInInputs := utils.ValidateInputs(params)

	if errorsInInputs != nil {
		return
	}

	// creating a http client
	httpClientObj, _ := utils.GetHttpClient(clientTimeOutInSeconds, verifyCa, certificate, certificateKey, zapLogger)

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(*httpClientObj, backoffDefinition, apiUrl, clientId, clientSecret, zapLogger, retryMaxElapsedTimeMinutes)

	// authenticating
	userObject, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger, maxFileSecretSizeBytes)

	secretPaths := []string{"fake/Client", "fake/test_file_1"}

	gotSecrets, _ := secretObj.GetSecrets(secretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotSecrets))

	// getting single secret
	gotSecret, _ := secretObj.GetSecret("fake/Test1", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("Secret Test: %v", gotSecret))

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	newSecretPaths := []string{"fake/account01", "fake/account01"}

	//managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(newSecretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	gotManagedAccount, _ := manageAccountObj.GetSecret("fake/account04", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccount))

	account := entities.AccountDetails{
		AccountName:                       "ManagedAccountTest",
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
		MaxReleaseDuration:                300000,
		ISAReleaseDuration:                180,
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
	}

	// creating a managed account in system_integration_test managed system.
	createResponse, err := manageAccountObj.ManageAccountCreateFlow("system_integration_test", account)

	if err != nil {
		zapLogger.Error(fmt.Sprintf(" %v", err))
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("Created Managed Account: %v", createResponse.AccountName))

	objCredential := entities.SecretCredentialDetails{
		Title:       "CREDENTIAL_" + uuid.New().String(),
		Description: "My Credential Secret Description",
		Username:    "my_user",
		Password:    "MyPass2#$!",
		OwnerType:   "User",
		Notes:       "My note",
		Owners: []entities.OwnerDetails{
			{
				OwnerId: userObject.UserId,
				Owner:   userObject.UserName,
				Email:   userObject.EmailAddress,
			},
		},
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	// creating a credential secret in folder1.
	createdSecret, err := secretObj.CreateSecretFlow("folder1", objCredential)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}
	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Credential secret: %v", createdSecret.Title))

	objText := entities.SecretTextDetails{
		Title:       "TEXT_" + uuid.New().String(),
		Description: "My Text Secret Description",
		Text:        "my_p4ssword!*2024",
		OwnerType:   "User",
		OwnerId:     userObject.UserId,
		FolderId:    uuid.New(),
		Owners: []entities.OwnerDetails{
			{
				OwnerId: userObject.UserId,
				Owner:   userObject.UserName,
				Email:   userObject.EmailAddress,
			},
		},
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	// creating a text secret in folder1.
	createdSecret, err = secretObj.CreateSecretFlow("folder1", objText)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}
	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Text secret: %v", createdSecret.Title))

	objFile := entities.SecretFileDetails{
		Title:       "FILE_" + uuid.New().String(),
		Description: "My File Secret Description",
		OwnerType:   "User",
		OwnerId:     userObject.UserId,
		Owners: []entities.OwnerDetails{
			{
				OwnerId: userObject.UserId,
				Owner:   userObject.UserName,
				Email:   userObject.EmailAddress,
			},
		},
		Notes:       "Notes 1",
		FileName:    "my_secret.txt",
		FileContent: "my_p4ssword!*2024",
		Urls: []entities.UrlDetails{
			{
				Id:           uuid.New(),
				CredentialId: uuid.New(),
				Url:          "https://www.test.com/",
			},
		},
	}

	// creating a file secret in folder1.
	createdSecret, err = secretObj.CreateSecretFlow("folder1", objFile)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created File secret: %v", createdSecret.Title))

	folderDetails := entities.FolderDetails{
		Name:        "FOLDER_" + uuid.New().String(),
		Description: "My Folder Secret Description",
	}

	// creating a folder secret in folder1 folder.
	createdFolder, err := secretObj.CreateFolderFlow("folder1", folderDetails)

	if err != nil {
		zapLogger.Error(err.Error())
		return
	}

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Debug(fmt.Sprintf("Created Folder: %v", createdFolder.Name))

	// signing out
	_ = authenticate.SignOut()

}
