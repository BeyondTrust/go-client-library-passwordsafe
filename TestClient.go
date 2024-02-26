package main

import (
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	logging "go-client-library-passwordsafe/api/logging"
	managed_accounts "go-client-library-passwordsafe/api/managed_account"
	"go-client-library-passwordsafe/api/secrets"
	"go-client-library-passwordsafe/api/utils"
	"strings"

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

	// validate inputs
	errors_in_inputs := utils.ValidateInputs(clientId, clientSecret, apiUrl, clientTimeOutInSeconds, &separator, verifyCa, zapLogger, certificate, certificateKey)

	if errors_in_inputs != nil {
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
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger)

	paths := "fake/text1,fake/text2"
	errors_in_path := utils.ValidatePath(paths)
	if errors_in_path != nil {
		return
	}

	// getting secrets
	secretPaths := strings.Split(paths, ",")
	gotSecrets, _ := secretObj.GetSecrets(secretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Info(fmt.Sprintf("%v", gotSecrets))

	// getting single secret
	gotSecret, _ := secretObj.GetSecret("fake/text1", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Info(fmt.Sprintf("Secret Test: %v", gotSecret))

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	paths = "fake/account01,fake/account02"
	errors_in_path = utils.ValidatePath(paths)
	if errors_in_path != nil {
		return
	}

	managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(managedAccountList, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	gotManagedAccount, _ := manageAccountObj.GetSecret("fake/account01", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccount))

	// signing out
	_ = authenticate.SignOut(fmt.Sprintf("%v%v", authenticate.ApiUrl, "Auth/Signout"))

}
