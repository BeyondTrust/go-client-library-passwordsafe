package main

import (
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	logging "go-client-library-passwordsafe/api/logging"
	managed_accounts "go-client-library-passwordsafe/api/managed_account"
	"go-client-library-passwordsafe/api/secrets"
	"go-client-library-passwordsafe/api/utils"

	"go.uber.org/zap"
)

// main funtion
func main() {

	// create a zap logger
	//logger, _ := zap.NewProduction()
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	apiUrl := "https://jury2310.ps-dev.beyondtrustcloud.com:443/BeyondTrust/api/public/v3/"
	clientId := "6138d050-e266-4b05-9ced-35e7dd5093ae"
	clientSecret := "8i7U0Yulabon8mTcOzJcltiEg4wYOhDVMerXva+Nuw8="
	separator := "/"
	certificate := ""
	certificateKey := ""
	clientTimeOutInSeconds := 30
	verifyCa := true
	retryMaxElapsedTimeMinutes := 2
	maxFileSecretSizeBytes := 4000

	// validate inputs
	errorsInInputs := utils.ValidateInputs(clientId, clientSecret, apiUrl, clientTimeOutInSeconds, &separator, verifyCa, zapLogger, certificate, certificateKey, &retryMaxElapsedTimeMinutes, &maxFileSecretSizeBytes)

	if errorsInInputs != nil {
		return
	}

	// creating a http client
	httpClientObj, _ := utils.GetHttpClient(clientTimeOutInSeconds, verifyCa, certificate, certificateKey, zapLogger)

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(*httpClientObj, apiUrl, clientId, clientSecret, zapLogger, retryMaxElapsedTimeMinutes)

	// authenticating
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger, maxFileSecretSizeBytes)

	//"oauthgrp/folder1/folder2/folder 3/folder4/folder5/folder6/text-test",
	//, "oauthgrp/folder1/folder2/folder 3/folder4/folder5/folder6/TextLongPath"
	secretPaths := []string{"oauthgrp/text1", "oauthgrp/folder1/folder2/secret"}

	gotSecrets, _ := secretObj.GetSecrets(secretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotSecrets))

	// getting single secret
	//gotSecret, _ := secretObj.GetSecret("fake/Test1", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	//zapLogger.Warn(fmt.Sprintf("Secret Test: %v", gotSecret))

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	newSecretPaths := []string{"system01/managed_account01", "system02/managed_account01"}

	//managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(newSecretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	//gotManagedAccount, _ := manageAccountObj.GetSecret("fake/account04", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	//zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccount))

	// signing out
	_ = authenticate.SignOut(fmt.Sprintf("%v%v", authenticate.ApiUrl, "Auth/Signout"))

}
