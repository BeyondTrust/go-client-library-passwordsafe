<a href="https://www.beyondtrust.com">
    <img src="assets/beyondtrust_logo.svg" alt="BeyondTrust" title="BeyondTrust" align="right" height="50">
</a>
# Go Client Library for Password Safe
The Go client library for Password Safe enables Go developers to easily manage passwords from Password Safe. It provide simplifications that significantly reduce the amount of code you need to write.
[![License](https://img.shields.io/badge/license-MIT%20-brightgreen.svg)](LICENSE)

## Prerequisites
The library supports retrieval of secrets from BeyondInsight/Password Safe versions 23.1 or greater.

## Retrieve Secrets
- apiUrl:
    - description: BeyondTrust Password Safe API URL.
    - type: string
    - required: True
- clientId:
    - description: API OAuth Client ID.
    - type: string
    - required: True
- clientSecret:
    - description: API OAuth Client Secret.
    - type: string
    - required: True
- secretPaths:
    - description: List of secrets ["path/title","path/title"] or managed accounts ["ms/ma","ms/ma"] to be retrieved, separated by a comma.
    - type: list
    - required: True
- certificate:
    - description: Content of the certificate (cert.pem) for use when authenticating with an API key using a Client Certificate.
    - type: string
    - required: False
- certificateKey:
    - description: Certificate private key (key.pem). For use when authenticating with an API key.
    - type: string
    - required: False
- verifyCA:
    - description: Indicates whether to verify the certificate authority on the Secrets Safe instance. Warning: false is insecure, instructs the Secrets Safe custom action not to verify the certificate authority.
    - type: boolean 
    - default: True
    - required: False
- separator
    - description: Indicates the separator used for Managed Accounts or Secrets Safe paths. The default separator is forwardslash. Use a different symbol, for example: root1-folder1-title1
    - type: string
    - default: /
    - required: False
- clientTimeOutInSeconds
    - description: Timeout specifies a time limit for requests made by this Client. The timeout includes connection time, any redirects, and reading the response body.
    - type: int
    - default: 30 seconds
    - required: False
- retryMaxElapsedTimeMinutes
    - description: After MaxElapsedTime the ExponentialBackOff returns Stop.
    - type: int
    - default: 2 minutes
    - required: False

## Methods
- getSecrets(paths)
	- Invoked for Managed Account or Secrets Safe secrets.
	- Returns a dictionary of secrets path/secret key value pair.
- getSecret(path)
	- Invoked for Managed Account or Secrets Safe secrets.
	- Returns the requested secret.

## Example of usage

The TestClient.go provides example usage of the library.

and execute:

```sh
go build
go run TestClient.go
```

## Extracting Client Secret
Download the pfx certificate from Secrets Safe and extract the certificate and the key.

~~~~
openssl pkcs12 -in client_certificate.pfx -nocerts -out ps_key.pem -nodes

openssl pkcs12 -in client_certificate.pfx -clcerts -nokeys -out ps_cert.pem
~~~~

Copy the text from the ps_key.pem to a secret.
```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```
Copy the text from the ps_cert.pem to a secret.
```
-----BEGIN CERTIFICATE----- 
... 
-----END CERTIFICATE-----
```
## Logging Abstraction
This library supports Zap, Logr, and go log package. The library can be extended to support other logging packages, see logging.go.
```
    // create a zap logger
	logger, _ := zap.NewProduction()
	// logger, _ := zap.NewDevelopment()

	// create a zap logger wrapper
	zapLogger := logging.NewZapLogger(logger)
```

## License
This software is distributed under the Massachusetts Institute of Technology (MIT) License. See `LICENSE.txt` for more information.

## Get Help
Contact [BeyondTrust support](https://www.beyondtrust.com/docs/index.htm#support)

## Release Please App usage

In order to use Release Please App, we need to use [Conventional commits](https://beyondtrust.atlassian.net/wiki/spaces/DEVOPS/pages/380699165/Releasing+Software#4.-Trigger-the-app), but [here](https://github.com/angular/angular/blob/22b96b9/CONTRIBUTING.md#type) is a more comprehensive guide about some conventional commits that we can use.

Some of the more important and common commit types are:

|Type    |Description                                                  |Triggers Release Please|
|:-------|:------------------------------------------------------------|:----------------------|
|feat!   |Introduce a major change e.g. v1.0.0 to v2.0.0               |Yes                    |
|feat    |Introduce a minor change e.g. v1.0.0 to v1.1.0               |Yes                    |
|fix     |Introduce a patch change e.g. v1.0.0 to v1.0.1               |Yes                    |
|chore   |Could introduce a BREAKING CHANGE into the CHANGELOG         |Yes                    |
|docs    |Documentation update                                         |No                     |
|refactor|A code change that neither fixes a bug nor adds a feature    |No                     |
|test    |Adding or modifying tests                                    |No                     |
|build   |Changes that affect the build system or external dependencies|No                     |
|ci      |Changes to CI configuration files and scripts                |No                     |

Remember, Release Please App will trigger once a PR with the conventional commit structure are merged into the main branch, so if you are working on features that are related to a Jira ticket, you can still use **feat** while developing, and because we can squash the commits once we want to merge the PR, only one commit with the conventional syntax will be on the history and on the changelog.