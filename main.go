package main

import (
	"fmt"
	"go-client-library-passwordsafe/api/authentication"
	managed_accounts "go-client-library-passwordsafe/api/managed_account"
	secrets "go-client-library-passwordsafe/api/secrets"
	"go-client-library-passwordsafe/api/utils"
	"log"
	"os"
	"strings"
)

var logger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)

// main funtion
func main() {

	//logFile, _ := os.Create("ProviderLogs.log")
	//logger.SetOutput(logFile)

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
	errors_in_inputs := utils.ValidateInputs(clientId, clientSecret, apiUrl, clientTimeOutinSeconds, separator, verifyCa, logger, certificate, certificate_key)

	if errors_in_inputs != nil {
		utils.Logging("ERROR", errors_in_inputs.Error(), *logger)
		return
	}

	// creating a http client
	httpClient, _ := utils.GetHttpClient(clientTimeOutinSeconds, verifyCa, certificate, certificate_key)

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(httpClient, apiUrl, clientId, clientSecret, logger, maxElapsedTime)

	// authenticating in PS API
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, *logger)

	// getting secrets
	secretList := strings.Split("oauthgrp/text2,oauthgrp/text1", ",")
	gotSecrets, _ := secretObj.GetSecrets(secretList, separator)
	utils.Logging("DEBUG", fmt.Sprintf("%v", gotSecrets), *logger)

	// getting secrets
	secretList = strings.Split("oauthgrp/text2", ",")
	gotSecret, _ := secretObj.GetSecret(secretList, separator)
	utils.Logging("DEBUG", fmt.Sprintf("%v", gotSecret), *logger)

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, *logger)

	// getting managed accounts
	managedAccountList := strings.Split("system01/managed_account01,system02/managed_account01", ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(managedAccountList, separator)
	utils.Logging("DEBUG", fmt.Sprintf("%v", gotManagedAccounts), *logger)

	// getting single managed account
	managedAccountList = []string{}
	gotManagedAccount, _ := manageAccountObj.GetSecret(append(managedAccountList, "system01/managed_account01"), separator)
	utils.Logging("DEBUG", fmt.Sprintf("%v", gotManagedAccount), *logger)

	// signing out
	authenticate.SignOut(fmt.Sprintf("%v%v", authenticate.ApiUrl, "Auth/Signout"))

}
