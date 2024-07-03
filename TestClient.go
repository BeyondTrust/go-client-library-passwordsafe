package main

import (
	"fmt"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	managed_accounts "github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_account"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

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

	apiUrl := "https://jury2310.ps-dev.beyondtrustcloud.com:443/BeyondTrust/api/public/v3/"
	clientId := "6138d050-e266-4b05-9ced-35e7dd5093ae"
	clientSecret := "71svdPLh2AR97sPs5gfPjGjpqSUxZTKSPmEvvbMx89o="
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
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	/*
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

	*/

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	newSecretPaths := []string{"system01/managed_account01", "system01/managed_account01"}

	//managedAccountList := strings.Split(paths, ",")
	gotManagedAccounts, _ := manageAccountObj.GetSecrets(newSecretPaths, separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccounts))

	// getting single managed account
	gotManagedAccount, _ := manageAccountObj.GetSecret("system01/managed_account01", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotManagedAccount))

	// signing out
	_ = authenticate.SignOut()

}
