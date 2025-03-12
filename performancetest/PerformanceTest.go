package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/pprof"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/secrets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

// number of PS API calls
const numberOfIterations = 5

func main() {
	go func() {
		err := http.ListenAndServe("localhost:6060", nil)
		if err != nil {
			panic(err)
		}
	}()

	// CPU
	f, err := os.Create("cpu.pprof")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = pprof.StartCPUProfile(f)
	if err != nil {
		panic(err)
	}
	defer pprof.StopCPUProfile()

	for i := 0; i < numberOfIterations-1; i++ {
		time.Sleep(100 * time.Millisecond)
		callPasswordSafeAPI()

	}

	// MEMORY: Take a memory snapshot
	f, _ = os.Create("memory.pprof")
	err = pprof.WriteHeapProfile(f)
	if err != nil {
		panic(err)
	}

	f.Close()
}

// Method to be tested
func callPasswordSafeAPI() {
	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	zapLogger.Info("Starting Performance Test execution")

	apiUrl := os.Getenv("PASSWORD_SAFE_API_URL")
	clientId := os.Getenv("PASSWORD_SAFE_CLIENT_ID")
	clientSecret := os.Getenv("PASSWORD_SAFE_CLIENT_SECRET")
	certificate := os.Getenv("PASSWORD_SAFE_CERTIFICATE")
	certificateKey := os.Getenv("PASSWORD_SAFE_CERTIFICATE_KEY")

	separator := "/"
	clientTimeOutInSeconds := 30
	verifyCa := true
	retryMaxElapsedTimeMinutes := 15
	maxFileSecretSizeBytes := 5000000

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

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.InitialInterval = 1 * time.Second
	backoffDefinition.MaxElapsedTime = time.Duration(retryMaxElapsedTimeMinutes) * time.Second
	backoffDefinition.RandomizationFactor = 0.5

	authParams := &authentication.AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                apiUrl,
		APIVersion:                 "3.1",
		ClientID:                   clientId,
		ClientSecret:               clientSecret,
		ApiKey:                     "",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: retryMaxElapsedTimeMinutes,
	}

	// instantiating authenticate obj, injecting httpClient object
	authenticate, _ := authentication.Authenticate(*authParams)

	// authenticating
	_, err := authenticate.GetPasswordSafeAuthentication()
	if err != nil {
		return
	}

	// instantiating secret obj
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger, maxFileSecretSizeBytes)

	// getting single secret
	gotSecret, _ := secretObj.GetSecret("oauthgrp/folder1/folder2/folder 3/folder4/folder5/folder6/Text-Test", separator)

	// WARNING: Do not log secrets in production code, the following log statement logs test secrets for testing purposes:
	zapLogger.Warn(fmt.Sprintf("%v", gotSecret))

	zapLogger.Info("Ending Performance Test execution")

	// signing out
	_ = authenticate.SignOut()

}
