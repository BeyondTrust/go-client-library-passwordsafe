// Copyright 2025 BeyondTrust. All rights reserved.
// Package constants.
package constants

import "os"

var (
	APIPath            = os.Getenv("PASSWORD_SAFE_API_PATH")
	FakeApiUrl         = os.Getenv("PASSWORD_SAFE_FAKE_API_URL")
	FakeClientId       = os.Getenv("PASSWORD_SAFE_FAKE_CLIENT_ID")
	FakeApiKey         = os.Getenv("PASSWORD_SAFE_FAKE_API_KEY")
	FakeClientSecret   = os.Getenv("PASSWORD_SAFE_FAKE_CLIENT_SECRET")
	ApiVersion31       = "3.1"
	Fakecertificate    = os.Getenv("PASSWORD_SAFE_FAKE_CERTIFICATE")
	FakecertificateKey = os.Getenv("PASSWORD_SAFE_FAKE_CERTIFICATE_KEY")
	FakePassword       = os.Getenv("PASSWORD_SAFE_FAKE_PASSWORD")
)
