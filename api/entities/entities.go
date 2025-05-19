// Copyright 2024 BeyondTrust. All rights reserved.
// Package entities implements DTO's used by Beyondtrust Secret Safe API.
package entities

import (
	"bytes"

	"github.com/google/uuid"
)

// SignAppinResponse responsbile for API sign in information.
type SignAppinResponse struct {
	UserId       int    `json:"UserId"`
	EmailAddress string `json:"EmailAddress"`
	UserName     string `json:"UserName"`
	Name         string `json:"Name"`
}

// ManagedAccount responsible for managed account response data.
type ManagedAccount struct {
	PlatformID             int
	SystemId               int
	SystemName             string
	DomainName             string
	AccountId              int
	AccountName            string
	InstanceName           string
	UserPrincipalName      string
	ApplicationID          int
	ApplicationDisplayName string
	DefaultReleaseDuration int
	MaximumReleaseDuration int
	LastChangeDate         string
	NextChangeDate         string
	IsChanging             bool
	ChangeState            int
	IsISAAccess            bool
	PreferredNodeID        string
	AccountDescription     string
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
	WorkgroupID                       int    `json:",omitempty" validate:"omitempty"`
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

type SecretCredentialDetailsConfig30 struct {
	SecretDetailsBaseConfig
	Username       string                `json:",omitempty" validate:"required"`
	Password       string                `json:",omitempty" validate:"max=256,required_without=PasswordRuleID"`
	OwnerId        int                   `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType      string                `json:",omitempty" validate:"required,oneof=User Group"`
	Owners         []OwnerDetailsOwnerId `json:",omitempty" validate:"required_if=OwnerType User"`
	PasswordRuleID int                   `json:",omitempty" validate:"omitempty"`
}

type SecretCredentialDetailsConfig31 struct {
	SecretDetailsBaseConfig
	Username       string                `json:",omitempty" validate:"required"`
	Password       string                `json:",omitempty" validate:"max=256,required_without=PasswordRuleID"`
	Owners         []OwnerDetailsGroupId `json:",omitempty" validate:"required_if=OwnerType User"`
	PasswordRuleID int                   `json:",omitempty" validate:"omitempty"`
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

type SecretDetailsBaseConfig struct {
	Title       string       `json:",omitempty" validate:"required,max=256"`
	Description string       `json:",omitempty" validate:"omitempty,max=256"`
	Notes       string       `json:",omitempty" validate:"omitempty,max=4000"`
	Urls        []UrlDetails `json:",omitempty" validate:"omitempty"`
}

type SecretTextDetailsConfig30 struct {
	SecretDetailsBaseConfig
	Text      string                `json:",omitempty" validate:"required,max=4096"`
	OwnerId   int                   `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType string                `json:",omitempty" validate:"required,oneof=User Group"`
	Owners    []OwnerDetailsOwnerId `json:",omitempty" validate:"required_if=OwnerType User"`
	FolderId  uuid.UUID             `json:",omitempty" validate:"omitempty"`
}

type SecretTextDetailsConfig31 struct {
	SecretDetailsBaseConfig
	Text     string                `json:",omitempty" validate:"required,max=4096"`
	Owners   []OwnerDetailsGroupId `json:",omitempty" validate:"required_if=OwnerType User"`
	FolderId uuid.UUID             `json:",omitempty" validate:"omitempty"`
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

type SecretFileDetailsConfig30 struct {
	SecretDetailsBaseConfig
	OwnerId     int                   `json:",omitempty" validate:"required_if=OwnerType Group"`
	OwnerType   string                `json:",omitempty" validate:"required,oneof=User Group"`
	Owners      []OwnerDetailsOwnerId `json:",omitempty" validate:"required_if=OwnerType User"`
	FileName    string                `json:",omitempty" validate:"required,max=256"`
	FileContent string                `json:",omitempty" validate:"required,max=5000000"`
}

type SecretFileDetailsConfig31 struct {
	SecretDetailsBaseConfig
	Owners      []OwnerDetailsGroupId `json:",omitempty" validate:"required_if=OwnerType User"`
	FileName    string                `json:",omitempty" validate:"required,max=256"`
	FileContent string                `json:",omitempty" validate:"required,max=5000000"`
}

type OwnerDetails struct {
	GroupId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	OwnerId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	Owner   string `json:",omitempty" validate:"omitempty"`
	Email   string `json:",omitempty" validate:"omitempty"`
}

type OwnerDetailsOwnerId struct {
	OwnerId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	Owner   string `json:",omitempty" validate:"omitempty"`
	Email   string `json:",omitempty" validate:"omitempty"`
}

type OwnerDetailsGroupId struct {
	GroupId int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	UserId  int    `json:",omitempty" validate:"required,min=1,max=2147483647"`
	Name    string `json:",omitempty" validate:"omitempty"`
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
	AccessToken string
	ApiKey      string
	ContentType string
	ApiVersion  string
}

type WorkGroupDetails struct {
	OrganizationID string `json:",omitempty" validate:"omitempty"`
	Name           string `json:",omitempty" validate:"required,max=256"`
}

type WorkGroupResponse struct {
	ID             int
	OrganizationID string
	Name           string
}

type AssetDetails struct {
	IPAddress       string `json:",omitempty" validate:"required,ip,max=46"`
	AssetName       string `json:",omitempty" validate:"omitempty,max=128"`
	DnsName         string `json:",omitempty" validate:"omitempty,max=255"`
	DomainName      string `json:",omitempty" validate:"omitempty,max=64"`
	MacAddress      string `json:",omitempty" validate:"omitempty,max=128"`
	AssetType       string `json:",omitempty" validate:"omitempty,max=64"`
	Description     string `json:",omitempty" validate:"omitempty,max=255"`
	OperatingSystem string `json:",omitempty" validate:"omitempty,max=255"`
}

type AssetResponse struct {
	WorkgroupID     int
	AssetID         int
	AssetName       string
	AssetType       string
	DnsName         string
	DomainName      string
	IPAddress       string
	OperatingSystem string
	CreateDate      string
	LastUpdateDate  string
	Description     string
}

type DatabaseDetails struct {
	PlatformID        int    `json:",omitempty" validate:"required"`
	InstanceName      string `json:",omitempty" validate:"required,max=100"`
	IsDefaultInstance bool   `json:",omitempty" `
	Port              int    `json:",omitempty" validate:"required,min=1,max=65535"`
	Version           string `json:",omitempty" validate:"omitempty,max=20"`
	Template          string `json:",omitempty" validate:"omitempty"`
}

type DatabaseResponse struct {
	AssetID           int
	DatabaseID        int
	PlatformID        int
	InstanceName      string
	IsDefaultInstance bool
	Port              int
	Version           string
	Template          string
}

type ManagedSystemsByAssetIdDetailsBaseConfig struct {
	PlatformID                        int    `json:"PlatformID" validate:"required"`
	ContactEmail                      string `json:"ContactEmail" validate:"max=1000"`
	Description                       string `json:"Description" validate:"max=255"`
	Port                              int    `json:"Port,omitempty"`
	Timeout                           int    `json:"Timeout,omitempty"`
	SshKeyEnforcementMode             int    `json:"SshKeyEnforcementMode,omitempty" validate:"oneof=0 1 2"`
	PasswordRuleID                    int    `json:"PasswordRuleID,omitempty"`
	DSSKeyRuleID                      int    `json:"DSSKeyRuleID,omitempty"`
	LoginAccountID                    int    `json:"LoginAccountID,omitempty"`
	ReleaseDuration                   int    `json:"ReleaseDuration" validate:"min=1,max=525600"`
	MaxReleaseDuration                int    `json:"MaxReleaseDuration" validate:"min=1,max=525600"`
	ISAReleaseDuration                int    `json:"ISAReleaseDuration" validate:"min=1,max=525600"`
	AutoManagementFlag                bool   `json:"AutoManagementFlag,omitempty"`
	FunctionalAccountID               int    `json:"FunctionalAccountID" validate:"required_if=AutoManagementFlag true"`
	ElevationCommand                  string `json:"ElevationCommand,omitempty"`
	CheckPasswordFlag                 bool   `json:"CheckPasswordFlag,omitempty"`
	ChangePasswordAfterAnyReleaseFlag bool   `json:"ChangePasswordAfterAnyReleaseFlag,omitempty"`
	ResetPasswordOnMismatchFlag       bool   `json:"ResetPasswordOnMismatchFlag,omitempty"`
	ChangeFrequencyType               string `json:"ChangeFrequencyType" validate:"oneof=first last xdays"`
	ChangeFrequencyDays               int    `json:"ChangeFrequencyDays,omitempty" validate:"required_if=ChangeFrequencyType xdays"`
	ChangeTime                        string `json:"ChangeTime" validate:"datetime=15:04"`
}

type ManagedSystemsByAssetIdDetailsConfig30 struct {
	ManagedSystemsByAssetIdDetailsBaseConfig
}

type ManagedSystemsByAssetIdDetailsConfig31 struct {
	ManagedSystemsByAssetIdDetailsBaseConfig
	RemoteClientType string `json:"RemoteClientType" validate:"oneof=None EPM"`
}

type ManagedSystemsByAssetIdDetailsConfig32 struct {
	ManagedSystemsByAssetIdDetailsBaseConfig
	RemoteClientType  string `json:"RemoteClientType" validate:"oneof=None EPM"`
	ApplicationHostID int    `json:"ApplicationHostID,omitempty"`
	IsApplicationHost bool   `json:"IsApplicationHost"`
}

type ManagedSystemResponseCreate struct {
	ManagedSystemID                    int    `json:"ManagedSystemID"`
	EntityTypeID                       int    `json:"EntityTypeID"`
	AssetID                            int    `json:"AssetID"`
	DatabaseID                         int    `json:"DatabaseID,omitempty"`
	DirectoryID                        int    `json:"DirectoryID,omitempty"`
	CloudID                            int    `json:"CloudID,omitempty"`
	WorkgroupID                        int    `json:"WorkgroupID"`
	HostName                           string `json:"HostName"`
	DnsName                            string `json:"DnsName"`
	IPAddress                          string `json:"IPAddress"`
	InstanceName                       string `json:"InstanceName,omitempty"`
	IsDefaultInstance                  bool   `json:"IsDefaultInstance,omitempty"`
	Template                           string `json:"Template,omitempty"`
	ForestName                         string `json:"ForestName,omitempty"`
	UseSSL                             bool   `json:"UseSSL,omitempty"`
	OracleInternetDirectoryID          string `json:"OracleInternetDirectoryID,omitempty"`
	OracleInternetDirectoryServiceName string `json:"OracleInternetDirectoryServiceName,omitempty"`
	SystemName                         string `json:"SystemName"`
	PlatformID                         int    `json:"PlatformID"`
	NetBiosName                        string `json:"NetBiosName,omitempty"`
	Port                               int    `json:"Port,omitempty"`
	Timeout                            int    `json:"Timeout"`
	Description                        string `json:"Description"`
	ContactEmail                       string `json:"ContactEmail"`
	PasswordRuleID                     int    `json:"PasswordRuleID"`
	DSSKeyRuleID                       int    `json:"DSSKeyRuleID"`
	ReleaseDuration                    int    `json:"ReleaseDuration"`
	MaxReleaseDuration                 int    `json:"MaxReleaseDuration"`
	ISAReleaseDuration                 int    `json:"ISAReleaseDuration"`
	AutoManagementFlag                 bool   `json:"AutoManagementFlag"`
	FunctionalAccountID                int    `json:"FunctionalAccountID,omitempty"`
	LoginAccountID                     int    `json:"LoginAccountID,omitempty"`
	ElevationCommand                   string `json:"ElevationCommand,omitempty"`
	SshKeyEnforcementMode              int    `json:"SshKeyEnforcementMode"`
	CheckPasswordFlag                  bool   `json:"CheckPasswordFlag"`
	ChangePasswordAfterAnyReleaseFlag  bool   `json:"ChangePasswordAfterAnyReleaseFlag"`
	ResetPasswordOnMismatchFlag        bool   `json:"ResetPasswordOnMismatchFlag"`
	ChangeFrequencyType                string `json:"ChangeFrequencyType"`
	ChangeFrequencyDays                int    `json:"ChangeFrequencyDays"`
	ChangeTime                         string `json:"ChangeTime"`
	AccountNameFormat                  int    `json:"AccountNameFormat"`
	RemoteClientType                   string `json:"RemoteClientType"`
	ApplicationHostID                  int    `json:"ApplicationHostID,omitempty"`
	IsApplicationHost                  bool   `json:"IsApplicationHost"`
	AccessURL                          string `json:"AccessURL,omitempty"`
}

type ManagedSystemsByWorkGroupIdDetailsBaseConfig struct {
	EntityTypeID                       int    `json:",omitempty" validate:"required"`
	HostName                           string `json:",omitempty" validate:"required,max=128"`
	IPAddress                          string `json:",omitempty" validate:"required,ip,max=46"`
	DnsName                            string `json:",omitempty" validate:"max=225"`
	InstanceName                       string `json:",omitempty" validate:"required_if=IsDefaultInstance true,max=100"`
	IsDefaultInstance                  bool   `json:",omitempty"`
	Template                           string `json:",omitempty"`
	ForestName                         string `json:",omitempty" validate:"max=64"`
	UseSSL                             bool   `json:",omitempty"`
	PlatformID                         int    `json:",omitempty" validate:"required"`
	NetBiosName                        string `json:",omitempty" validate:"max=15"`
	ContactEmail                       string `json:",omitempty" validate:"email,max=1000"`
	Description                        string `json:",omitempty" validate:"max=255"`
	Port                               int    `json:",omitempty"`
	Timeout                            int    `json:",omitempty"`
	SshKeyEnforcementMode              int    `json:",omitempty" validate:"oneof=0 1 2"`
	PasswordRuleID                     int    `json:",omitempty"`
	DSSKeyRuleID                       int    `json:",omitempty"`
	LoginAccountID                     int    `json:",omitempty"`
	AccountNameFormat                  int    `json:",omitempty" validate:"oneof=0 1 2"`
	OracleInternetDirectoryID          string `json:",omitempty"`
	OracleInternetDirectoryServiceName string `json:",omitempty" validate:"max=200"`
	ReleaseDuration                    int    `json:",omitempty" validate:"min=1,max=525600"`
	MaxReleaseDuration                 int    `json:",omitempty" validate:"min=1,max=525600"`
	ISAReleaseDuration                 int    `json:",omitempty" validate:"min=1,max=525600"`
	AutoManagementFlag                 bool   `json:",omitempty"`
	FunctionalAccountID                int    `json:",omitempty" validate:"required_if=AutoManagementFlag true"`
	ElevationCommand                   string `json:",omitempty"`
	CheckPasswordFlag                  bool   `json:",omitempty"`
	ChangePasswordAfterAnyReleaseFlag  bool   `json:",omitempty"`
	ResetPasswordOnMismatchFlag        bool   `json:",omitempty"`
	ChangeFrequencyType                string `json:",omitempty" validate:"oneof=first last xdays"`
	ChangeFrequencyDays                int    `json:",omitempty" validate:"required_if=ChangeFrequencyType xdays"`
	ChangeTime                         string `json:",omitempty" validate:"datetime=15:04"`
	AccessURL                          string `json:",omitempty" validate:"required,url"`
}

type ManagedSystemsByWorkGroupIdDetailsConfig30 struct {
	ManagedSystemsByWorkGroupIdDetailsBaseConfig
}

type ManagedSystemsByWorkGroupIdDetailsConfig31 struct {
	ManagedSystemsByWorkGroupIdDetailsBaseConfig
	RemoteClientType string `json:"RemoteClientType" validate:"oneof=None EPM"`
}

type ManagedSystemsByWorkGroupIdDetailsConfig32 struct {
	ManagedSystemsByWorkGroupIdDetailsBaseConfig
	RemoteClientType  string `json:"RemoteClientType" validate:"oneof=None EPM"`
	ApplicationHostID int    `json:"ApplicationHostID,omitempty"`
	IsApplicationHost bool   `json:"IsApplicationHost"`
}

type ManagedSystemsByWorkGroupIdDetailsConfig33 struct {
	ManagedSystemsByWorkGroupIdDetailsBaseConfig
	RemoteClientType  string `json:"RemoteClientType" validate:"oneof=None EPM"`
	ApplicationHostID int    `json:"ApplicationHostID,omitempty"`
	IsApplicationHost bool   `json:"IsApplicationHost"`
}

type ManagedSystemsByDatabaseIdDetailsBaseConfig struct {
	ContactEmail                      string `json:",omitempty" validate:"max=1000"`
	Description                       string `json:",omitempty" validate:"max=255"`
	Timeout                           int    `json:",omitempty" validate:"min=1"`
	PasswordRuleID                    int    `json:",omitempty"`
	ReleaseDuration                   int    `json:",omitempty" validate:"min=1,max=525600"`
	MaxReleaseDuration                int    `json:",omitempty" validate:"min=1,max=525600"`
	ISAReleaseDuration                int    `json:",omitempty" validate:"min=1,max=525600"`
	AutoManagementFlag                bool   `json:",omitempty"`
	FunctionalAccountID               int    `json:",omitempty" validate:"required_if=AutoManagementFlag true"`
	CheckPasswordFlag                 bool   `json:",omitempty"`
	ChangePasswordAfterAnyReleaseFlag bool   `json:",omitempty"`
	ResetPasswordOnMismatchFlag       bool   `json:",omitempty"`
	ChangeFrequencyType               string `json:",omitempty" validate:"oneof=first last xdays"`
	ChangeFrequencyDays               int    `json:",omitempty" validate:"required_if=ChangeFrequencyType xdays"`
	ChangeTime                        string `json:",omitempty" validate:"datetime=15:04"`
}

type FunctionalAccountDetails struct {
	PlatformID          int    `validate:"required"`
	DomainName          string `validate:"omitempty,max=500"`
	AccountName         string `validate:"required,max=245"`
	DisplayName         string `validate:"omitempty,max=100"`
	Password            string `validate:"omitempty"`
	PrivateKey          string `validate:"omitempty"`
	Passphrase          string `validate:"omitempty"`
	Description         string `validate:"omitempty,max=1000"`
	ElevationCommand    string `validate:"omitempty,max=80"`
	TenantID            string `validate:"omitempty,max=36"`
	ObjectID            string `validate:"omitempty,max=36"`
	Secret              string `validate:"omitempty,max=255"`
	ServiceAccountEmail string `validate:"omitempty,max=255"`
	AzureInstance       string `validate:"omitempty,oneof=AzurePublic AzureUsGovernment"`
}

type FunctionalAccountResponse struct {
	FunctionalAccountID  int
	PlatformID           int
	DomainName           string
	AccountName          string
	DisplayName          string
	Description          string
	ElevationCommand     string
	SystemReferenceCount int
	TenantID             string
	ObjectID             string
	AzureInstance        string
}

type PlatformResponse struct {
	PlatformID              int
	Name                    string
	ShortName               string
	PortFlag                bool
	DefaultPort             int
	SupportsElevationFlag   bool
	DomainNameFlag          bool
	AutoManagementFlag      bool
	DSSAutoManagementFlag   bool
	ManageableFlag          bool
	DSSFlag                 bool
	LoginAccountFlag        bool
	DefaultSessionType      string
	ApplicationHostFlag     bool
	RequiresApplicationHost bool
	RequiresTenantID        bool
	RequiresObjectID        bool
	RequiresSecret          bool
}
