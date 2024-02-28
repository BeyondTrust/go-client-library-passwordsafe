// Copyright 2024 BeyondTrust. All rights reserved.
// Package entities implements DTO's used by Beyondtrust Secret Safe API.
package entities

// SignApinResponse responsbile for API sign in information.
type SignApinResponse struct {
	UserId       int    `json:"UserId"`
	EmailAddress string `json:"EmailAddress"`
	UserName     string `json:"UserName"`
	Name         string `json:"Name"`
}

// ManagedAccount responsible for managed account response data.
type ManagedAccount struct {
	SystemId  int
	AccountId int
}

// Secret responsible for secrets-safe response data.
type Secret struct {
	Id         string
	Title      string
	Password   string
	SecretType string
}

// GetTokenResponse responsible for token response data.
type GetTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}
