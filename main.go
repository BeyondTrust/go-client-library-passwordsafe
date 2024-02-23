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

//var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)

// main funtion
func main() {

	//logFile, _ := os.Create("ProviderLogs.log")
	//logger.SetOutput(logFile)

	// create a zap logger
	//logger, _ := zap.NewProduction()
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	apiUrl := "https://jury2310.ps-dev.beyondtrustcloud.com:443/BeyondTrust/api/public/v3/"
	clientId := ""
	clientSecret := ""
	separator := "/"
	certificate := ""
	certificate_key := ""
	clientTimeOutinSeconds := 5
	verifyCa := true
	maxElapsedTime := 15

	// validate inputs
	errors_in_inputs := utils.ValidateInputs(clientId, clientSecret, apiUrl, clientTimeOutinSeconds, &separator, verifyCa, zapLogger, certificate, certificate_key)

	if errors_in_inputs != nil {
		return
	}

	// creating a http client
	httpClientObj, _ := utils.GetHttpClient(clientTimeOutinSeconds, verifyCa, certificate, certificate_key, zapLogger)

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(*httpClientObj, apiUrl, clientId, clientSecret, zapLogger, maxElapsedTime)

	// authenticating in PS API
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger)

	paths := "oauthgrp/text1,oauthgrp/text2"
	errors_in_path := utils.ValidatePath(paths)
	if errors_in_path != nil {
		return
	}

	// getting secrets
	secretList := strings.Split(paths, ",")
	gotSecrets, _ := secretObj.GetSecrets(secretList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotSecrets))

	// getting single secret
	secretList = strings.Split("oauthgrp/text1", ",")
	gotSecret, _ := secretObj.GetSecret(secretList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotSecret))

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	paths = "system01/managed_account01,system02/managed_account01"
	errors_in_path = utils.ValidatePath(paths)
	if errors_in_path != nil {
		return
	}

	managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(managedAccountList, separator)
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	managedAccountList = []string{}
	gotManagedAccount, _ := manageAccountObj.GetSecret(append(managedAccountList, "system01/managed_account01"), separator)
	zapLogger.Info(fmt.Sprintf("%v", gotManagedAccount))

	// signing out
	_ = authenticate.SignOut(fmt.Sprintf("%v%v", authenticate.ApiUrl, "Auth/Signout"))

}
