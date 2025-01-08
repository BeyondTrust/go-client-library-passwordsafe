package fuzzing_managed_account

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	managed_accounts "github.com/BeyondTrust/go-client-library-passwordsafe/api/managed_account"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	backoff "github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

type TestConfig struct {
	name     string
	server   *httptest.Server
	response string
}

func FuzzGetManagedAccount(f *testing.F) {

	testConfig := TestConfig{
		name: "FuzzGetManagedAccount",
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

			case "/ManagedAccounts":
				_, err := w.Write([]byte(`{"SystemId":1,"AccountId":10}`))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/Requests":
				_, err := w.Write([]byte(`124`))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/Credentials/124":
				_, err := w.Write([]byte(`"fake_credential"`))
				if err != nil {
					f.Error("Test case Failed")
				}

			case "/Requests/124/checkin":
				_, err := w.Write([]byte(``))
				if err != nil {
					f.Error("Test case Failed")
				}

			default:
				http.NotFound(w, r)
			}
		})),
		response: "fake_credential",
	}

	logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)

	httpClientObj, _ := utils.GetHttpClient(5, false, "", "", zapLogger)

	backoffDefinition := backoff.NewExponentialBackOff()
	backoffDefinition.MaxElapsedTime = time.Second

	// instantiating authenticate obj, injecting httpClient object
	var authenticate, _ = authentication.Authenticate(*httpClientObj, backoffDefinition, "https://fake.api.com:443/BeyondTrust/api/public/v3/", "fakeone_a654+9sdf7+8we4f", "fakeone_aasd156465sfdef", zapLogger, 300)

	apiUrl, _ := url.Parse(testConfig.server.URL + "/")
	authenticate.ApiUrl = *apiUrl

	// instantiating managed account obj
	manageAccountObj, _ := managed_accounts.NewManagedAccountObj(*authenticate, zapLogger)

	f.Add("fake1/account01", "/")
	f.Add("fake2/account02", "#")
	f.Add("fake3/account03", "*")
	f.Add("fake4/account04", "-")
	f.Add("fake5/account05", "/")

	f.Add("fake6/account06/test/test", "*//")
	f.Add("fake6/account06", "_")
	f.Add("fake6/account06/test/test", "*//***************")

	f.Fuzz(func(t *testing.T, a string, b string) {

		managedAccount, err := manageAccountObj.GetSecret(a, b)
		if err != nil {
			if !strings.Contains(err.Error(), "empty managed account list") {
				t.Errorf("Unexpected error: %s", err.Error())
			}
		}

		if err != nil && managedAccount != "" {
			t.Errorf("Unexpected error: %s", err.Error())
		}

	})

	// signing out
	_ = authenticate.SignOut()

}
