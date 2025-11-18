// Copyright 2025 BeyondTrust. All rights reserved.
// Package constants.
package constants

const (
	SecretGetSecretByPath  = "SecretGetSecretByPath"
	SecretGetFileSecret    = "SecretGetFileSecret"
	SecretCreateSecret     = "SecretCreateSecret"
	SecretGetFolders       = "SecretGetFolders"
	SecretGetSafes         = "SecretGetSafes"
	SecretCreateFolder     = "SecretCreateFolder"
	SecretCreateSafes      = "SecretCreateSafes"
	SecretDeleteSecret     = "SecretDeleteSecret"
	SecretDeleteFolder     = "SecretDeleteFolder"
	SecretDeleteSafe       = "SecretDeleteSafe"
	SecretGetSecretByTitle = "SecretGetSecretByTitle"

	ManagedAccountGet    = "ManagedAccountGet"
	ManagedAccountCreate = "ManagedAccountCreate"
	ManagedAccountDelete = "ManagedAccountDelete"

	ManagedAccountCreateRequest        = "ManagedAccountCreateRequest"
	CredentialByRequestId              = "CredentialByRequestId"
	ManagedAccountRequestCheckIn       = "ManagedAccountRequestCheckIn"
	ManagedAccountCreateManagedAccount = "ManagedAccountCreateManagedAccount"
	ManagedSystemGetSystems            = "ManagedSystemGetSystems"

	CreateMultiPartRequest = "CreateMultiPartRequest"

	SignOut   = "SignOut"
	GetToken  = "GetToken"
	SignAppin = "SignAppin"

	CreateWorkGroup   = "CreateWorkGroup"
	GetWorkGroupsList = "GetWorkGroupsList"

	CreateAsset                  = "CreateAsset"
	DeleteAsset                  = "DeleteAsset"
	GetAssetsListByWorkgroupId   = "GetAssetsListByWorkgroupId"
	GetAssetsListByWorkgroupName = "GetAssetsListByWorkgroupName"

	CreateDatabase   = "CreateDatabase"
	DeleteDatabase   = "DeleteDatabase"
	GetDataBasesList = "GetDataBasesList"

	CreateManagedSystemByAssetId     = "CreateManagedSystemByAssetId"
	CreateManagedSystemByWorkGroupId = "CreateManagedSystemByWorkGroupId"
	CreateManagedSystemByDataBaseId  = "CreateManagedSystemByDataBaseId"
	DeleteManagedSystem              = "DeleteManagedSystem"
	GetManagedSystemsList            = "GetManagedSystemsList"

	CreateFunctionalAccount = "CreateFunctionalAccount"
	DeleteFunctionalAccount = "DeleteFunctionalAccount"
	GetFunctionalAccount    = "GetFunctionalAccount"

	GetPlatformsList = "GetPlatformsList"
)
