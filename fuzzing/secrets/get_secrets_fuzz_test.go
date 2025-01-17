package fuzzing_secrets

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/secrets"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"

	"go.uber.org/zap"

	backoff "github.com/cenkalti/backoff/v4"
)

type TestConfig struct {
	name     string
	server   *httptest.Server
	response string
}

<<<<<<< HEAD
=======
// the recommended version is 3.1. If no version is specified,
// the default API version 3.0 will be used
var apiVersion string = "3.1"

>>>>>>> main
func FuzzGetSecret(f *testing.F) {

	testConfig := TestConfig{
		name: "FuzzGetSecret",
		server: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mocking Response according to the endpoint path
			switch r.URL.Path {

			case "/Auth/SignAppin":
				_, err := w.Write([]byte(`{"UserId":1, "EmailAddress":"Felipe"}`))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/Auth/Signout":
				_, err := w.Write([]byte(``))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/secrets-safe/secrets":
				_, err := w.Write([]byte(`[{"SecretType": "TEXT", "Password": "credential_in_sub_3_password","Id": "9152f5b6-07d6-4955-175a-08db047219ce","Title": "credential_in_sub_3"}]`))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/secrets-safe/secrets/9152f5b6-07d6-4955-175a-08db047219ce/file/download":
				_, err := w.Write([]byte(`fake_password`))
				if err != nil {
					f.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_password",
	}

	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

<<<<<<< HEAD
	// instantiating authenticate obj, injecting httpClient object
	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)
=======
	authParamsOauth := &authentication.AuthenticationParametersObj{
		HTTPClient:                 *httpClientObj,
		BackoffDefinition:          backoffDefinition,
		EndpointURL:                "https://fake.api.com:443/BeyondTrust/api/public/v3/",
		APIVersion:                 apiVersion,
		ClientID:                   "fakeone_a654+9sdf7+8we4f",
		ClientSecret:               "fakeone_a654+9sdf7+8we4f",
		ApiKey:                     "",
		Logger:                     zapLogger,
		RetryMaxElapsedTimeSeconds: 300,
	}

	// instantiating authenticate obj, injecting httpClient object
	var authenticate, _ = authentication.Authenticate(*authParamsOauth)
>>>>>>> main

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl
	secretObj, _ := secrets.NewSecretObj(*authenticate, zapLogger, 4000)

	f.Add("fake/Test1", "/")
	f.Add("fake/Test2", "*")
	f.Add("fake/Test3", "-")
	f.Add("fake/Test4", "+")

	f.Add("fake1/Test1/Test4", "//")
	f.Add("fake1/Test2/Test5", "")
	f.Add("fake1/Test1/Test4/Test5/Title", "-")
	f.Add("fake1/Test4", "+")

	f.Fuzz(func(t *testing.T, a string, b string) {

		secret, err := secretObj.GetSecret(a, b)
		if err != nil {
			if err.Error() != "empty secret list" {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if err != nil && secret != "" {
				t.Errorf("Unexpected error: %s", err.Error())
			}
		}

	})

	// signing out
	_ = authenticate.SignOut()

}
