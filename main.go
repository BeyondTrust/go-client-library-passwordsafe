package main

import (
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	logging "go-client-library-passwordsafe/api/logging"
	managed_accounts "go-client-library-passwordsafe/api/managed_account"
	secrets "go-client-library-passwordsafe/api/secrets"
	"go-client-library-passwordsafe/api/utils"
	"strings"

	"go.uber.org/zap"
)

//var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)

// main funtion
func main() {

	//logFile, _ := os.Create("ProviderLogs.log")
	//logger.SetOutput(logFile)

	// create a zap logger
	//logger, _ := zap.NewProduction()
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	apiUrl := "https://jury2310.ps-dev.beyondtrustcloud.com:443/BeyondTrust/api/public/v3/"
	clientId := ""
	clientSecret := ""
	separator := "/"
	certificate := ""
	certificate_key := ""
	clientTimeOutinSeconds := 30
	verifyCa := true
	maxElapsedTime := 15

	// validate inputs
	errors_in_inputs := utils.ValidateInputs(clientId, clientSecret, apiUrl, clientTimeOutinSeconds, separator, verifyCa, zapLogger, certificate, certificate_key)

	if errors_in_inputs != nil {

		//utils.Logging("ERROR", errors_in_inputs.Error(), *logger)
		return
	}

	// creating a http client
	httpClient, _ := utils.GetHttpClient(clientTimeOutinSeconds, verifyCa, certificate, certificate_key)

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(httpClient, apiUrl, clientId, clientSecret, zapLogger, maxElapsedTime)

	// authenticating in PS API
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger)

	// getting secrets
	secretList := strings.Split("oauthgrp/text2,oauthgrp/text1", ",")
	gotSecrets, _ := secretObj.GetSecrets(secretList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotSecrets))
	//utils.Logging("DEBUG", fmt.Sprintf("%v", gotSecrets), zapLogger)

	// getting secrets
	secretList = strings.Split("oauthgrp/text2", ",")
	gotSecret, _ := secretObj.GetSecret(secretList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotSecret))
	//utils.Logging("DEBUG", fmt.Sprintf("%v", gotSecret), *logger)

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	// getting managed accounts
	managedAccountList := strings.Split("system01/managed_account01,system02/managed_account01", ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(managedAccountList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccounts))
	//utils.Logging("DEBUG", fmt.Sprintf("%v", gotManagedAccounts), *logger)

	// getting single managed account
	managedAccountList = []string{}
	gotManagedAccount, _ := manageAccountObj.GetSecret(append(managedAccountList, "system01/managed_account01"), separator)
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccount))
	//utils.Logging("DEBUG", fmt.Sprintf("%v", gotManagedAccount), *logger)

	// signing out
	authenticate.SignOut(fmt.Sprintf("%v%v", authenticate.ApiUrl, "Auth/Signout"))

}
