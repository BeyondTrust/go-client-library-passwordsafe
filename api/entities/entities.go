// Copyright 2024 BeyondTrust. All rights reserved.
// Package entities implements DTO's used by Beyondtrust Secret Safe API.
package entities

import (
	"bytes"

	"github.com/google/uuid"
)

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

type ManagedSystemResponse struct {
	ManagedSystemID int
	SystemName      string
}

type CreateManagedAccountsResponse struct {
	ManagedAccountID int
	ManagedSystemID  int
	AccountName      string
}

type AccountDetails struct {
	AccountName                       string `validate:"required,max=245"`
	Password                          string `validate:"required_if=AutoManagementFlag false"`
	DomainName                        string `validate:"max=50"`
	UserPrincipalName                 string `validate:"omitempty,max=500"`
	SAMAccountName                    string `validate:"omitempty,max=20"`
	DistinguishedName                 string `validate:"omitempty,max=1000"`
	PrivateKey                        string `validate:"omitempty"`
	Passphrase                        string `validate:"omitempty,required_if=PrivateKey Encrypted"`
	PasswordFallbackFlag              bool   `validate:"omitempty"`
	LoginAccountFlag                  bool   `validate:"omitempty"`
	Description                       string `validate:"omitempty,max=1024"`
	PasswordRuleID                    int    `validate:"omitempty,gte=0"`
	ApiEnabled                        bool   `validate:"omitempty"`
	ReleaseNotificationEmail          string `validate:"omitempty,email,max=255"`
	ChangeServicesFlag                bool   `validate:"omitempty"`
	RestartServicesFlag               bool   `validate:"omitempty"`
	ChangeTasksFlag                   bool   `validate:"omitempty"`
	ReleaseDuration                   int    `validate:"omitempty,min=1,max=525600,ltefield=MaxReleaseDuration"`
	MaxReleaseDuration                int    `validate:"omitempty,min=1,max=525600"`
	ISAReleaseDuration                int    `validate:"omitempty,min=1,max=525600"`
	MaxConcurrentRequests             int    `validate:"omitempty,min=0,max=999"`
	AutoManagementFlag                bool   `validate:"omitempty"`
	DSSAutoManagementFlag             bool   `validate:"omitempty"`
	CheckPasswordFlag                 bool   `validate:"omitempty"`
	ChangePasswordAfterAnyReleaseFlag bool   `validate:"omitempty"`
	ResetPasswordOnMismatchFlag       bool   `validate:"omitempty"`
	ChangeFrequencyType               string `validate:"omitempty,oneof=first last xdays"`
	ChangeFrequencyDays               int    `validate:"omitempty,min=1,max=999"`
	ChangeTime                        string `validate:"omitempty,datetime=15:04"`
	NextChangeDate                    string `validate:"omitempty,datetime=2006-01-02"`
	UseOwnCredentials                 bool   `validate:"omitempty"`
	WorkgroupID                       *int   `validate:"omitempty"`
	ChangeWindowsAutoLogonFlag        bool   `validate:"omitempty"`
	ChangeComPlusFlag                 bool   `validate:"omitempty"`
	ChangeDComFlag                    bool   `validate:"omitempty"`
	ChangeSComFlag                    bool   `validate:"omitempty"`
	ObjectID                          string `validate:"omitempty,max=36"`
}

type FolderResponse struct {
	Id          string
	Name        string
	Description string
}

type CreateSecretResponse struct {
	Id          string
	Title       string
	Description string
	FolderId    string
}

type SecretCredentialDetails struct {
	Title          string         `json:",omitempty" validate:"required"`
	Description    string         `json:",omitempty" validate:"omitempty,max=256"`
	Username       string         `json:",omitempty" validate:"required"`
	Password       string         `json:",omitempty" validate:"max=256,required_without=PasswordRuleID"`
	OwnerId        int            `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType      string         `json:",omitempty" validate:"required,oneof=User Group"`
	Owners         []OwnerDetails `json:",omitempty" validate:"required_if=OwnerType User"`
	Notes          string         `json:",omitempty" validate:"omitempty,max=4000"`
	Urls           []UrlDetails   `json:",omitempty" validate:"omitempty"`
	PasswordRuleID int            `json:",omitempty" validate:"omitempty"`
}

type SecretTextDetails struct {
	Title       string         `json:",omitempty" validate:"required,max=256"`
	Description string         `json:",omitempty" validate:"omitempty,max=256"`
	Text        string         `json:",omitempty" validate:"required,max=4096"`
	OwnerId     int            `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType   string         `json:",omitempty" validate:"required,oneof=User Group"`
	Owners      []OwnerDetails `json:",omitempty" validate:"required_if=OwnerType User"`
	Notes       string         `json:",omitempty" validate:"omitempty,max=4000"`
	FolderId    uuid.UUID      `json:",omitempty" validate:"omitempty"`
	Urls        []UrlDetails   `json:",omitempty" validate:"omitempty"`
}

type SecretFileDetails struct {
	Title       string         `json:",omitempty" validate:"required,max=256"`
	Description string         `json:",omitempty" validate:"omitempty,max=256"`
	OwnerId     int            `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType   string         `json:",omitempty" validate:"required,oneof=User Group"`
	Owners      []OwnerDetails `json:",omitempty" validate:"required_if=OwnerType User"`
	Notes       string         `json:",omitempty" validate:"omitempty,max=4000"`
	FileName    string         `json:",omitempty" validate:"required,max=256"`
	FileContent string         `json:",omitempty" validate:"required,max=5000000"`
	Urls        []UrlDetails   `json:",omitempty" validate:"omitempty"`
}

type OwnerDetails struct {
	GroupId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	OwnerId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	Owner   string `json:",omitempty" validate:"omitempty"`
	Email   string `json:",omitempty" validate:"omitempty"`
}

type UrlDetails struct {
	Id           uuid.UUID `json:",omitempty" validate:"omitempty,uuid"`
	CredentialId uuid.UUID `json:",omitempty" validate:"omitempty,uuid"`
	Url          string    `json:",omitempty" validate:"required,max=2048,url"`
}

type CreateFolderResponse struct {
	Id          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ParentId    uuid.UUID `json:"parentId"`
	UserGroupId int       `json:"userGroupId"`
}

type FolderDetails struct {
	Name        string    `json:",omitempty" validate:"required"`
	Description string    `json:",omitempty" validate:"omitempty,max=256"`
	ParentId    uuid.UUID `json:",omitempty" validate:"required_if=FolderType FOLDER"`
	UserGroupId int       `json:",omitempty" validate:"omitempty"`
	FolderType  string    `json:",omitempty" validate:"required"`
}

type CallSecretSafeAPIObj struct {
	Url         string
	HttpMethod  string
	Body        bytes.Buffer
	Method      string
	AccesToken  string
	ApiKey      string
	ContentType string
}

type WorkGroupDetails struct {
	OrganizationID string `json:",omitempty" validate:"omitempty"`
	Name           string `json:",omitempty" validate:"required,max=256"`
}

type WorkGroupResponse struct {
	ID             int    `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
}
