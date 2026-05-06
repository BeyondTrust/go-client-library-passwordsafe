// Copyright 2024 BeyondTrust. All rights reserved.
// Package secrets implements Get secret logic for Secrets Safe (cred, text, file)
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/authentication"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/utils"
	"github.com/google/uuid"

	backoff "github.com/cenkalti/backoff/v4"
)

// SecretObj responsible for session requests.
type SecretObj struct {
	log                    logging.Logger
	authenticationObj      authentication.AuthenticationObj
	maxFileSecretSizeBytes int
	decrypt                bool
}

// NewSecretObj creates secret obj
func NewSecretObj(authentication authentication.AuthenticationObj, logger logging.Logger, maxFileSecretSizeBytes int, decrypt bool) (*SecretObj, error) {
	secretObj := &SecretObj{
		log:                    logger,
		authenticationObj:      authentication,
		maxFileSecretSizeBytes: maxFileSecretSizeBytes,
		decrypt:                decrypt,
	}
	return secretObj, nil
}

// GetSecrets returns secret value for a path and title list.
func (secretObj *SecretObj) GetSecrets(secretPaths []string, separator string) (map[string]string, error) {
	return secretObj.GetSecretFlow(secretPaths, separator)
}

// GetSecret returns secret value for a specific path and title.
func (secretObj *SecretObj) GetSecret(secretPath string, separator string) (string, error) {
	secretPaths := []string{}
	secrets, err := secretObj.GetSecretFlow(append(secretPaths, secretPath), separator)
	secretValue := secrets[secretPath]
	return secretValue, err
}

// GetFileSecret Get data of a file secret.
func (secretObj *SecretObj) GetFileSecret(secret entities.Secret, secretPath string) (string, error) {
	fileSecretContent, err := secretObj.SecretGetFileSecret(secret.Id, "secrets-safe/secrets/")
	if err != nil {
		return "", err
	}

	secretInBytes := []byte(fileSecretContent)

	if len(secretInBytes) > secretObj.maxFileSecretSizeBytes {
		return "", fmt.Errorf("%v: %v %v %v %v", secretPath, "Secret file Size:", len(secretInBytes), "is greater than the maximum allowed size:", secretObj.maxFileSecretSizeBytes)
	} else {
		return fileSecretContent, nil
	}
}

// GetGeneralSecret Get general data of a secret.
func (secretObj *SecretObj) GetGeneralSecret(secretPath string, secretTitle string, separator string) (entities.Secret, error) {

	var err error
	secret, err := secretObj.SecretGetSecretByPath(secretPath, secretTitle, separator, "secrets-safe/secrets")

	entireSecretPath := secretPath + separator + secretTitle

	if err != nil {
		saveLastErr := err
		secretObj.log.Error(err.Error() + "secretPath:" + entireSecretPath)
		return entities.Secret{}, saveLastErr
	}

	return secret, nil
}

// SplitGetSecretPathAndSecretTitle Split entire secret path and get path and title.
func (secretObj *SecretObj) SplitGetSecretPathAndSecretTitle(secretToRetrieve string, separator string) (string, string) {
	retrievalData := strings.Split(secretToRetrieve, separator)
	secretTitle := retrievalData[len(retrievalData)-1]
	secretPath := retrievalData[0]
	if len(retrievalData) > 2 {
		_, retrievalData = retrievalData[len(retrievalData)-1], retrievalData[:len(retrievalData)-1]
		secretPath = strings.TrimSuffix(strings.Join(retrievalData, separator), separator)
	}
	return secretPath, secretTitle
}

// GetSecretFlow is responsible for creating a dictionary of secrets safe secret paths and secret key-value pairs.
func (secretObj *SecretObj) GetSecretFlow(secretsToRetrieve []string, separator string) (map[string]string, error) {

	secretsToRetrieve = utils.ValidatePaths(secretsToRetrieve, false, separator, secretObj.log)
	secretObj.log.Info(fmt.Sprintf("Retrieving %v Secrets", len(secretsToRetrieve)))
	secretDictionary := make(map[string]string)
	var saveLastErr error = nil

	if len(secretsToRetrieve) == 0 {
		return secretDictionary, errors.New("empty secret list")
	}

	for _, secretToRetrieve := range secretsToRetrieve {

		secretPath, secretTitle := secretObj.SplitGetSecretPathAndSecretTitle(secretToRetrieve, separator)
		entireSecretPath := secretPath + separator + secretTitle

		secret, err := secretObj.GetGeneralSecret(secretPath, secretTitle, separator)

		if err != nil {
			saveLastErr = err
			secretObj.log.Error(err.Error())
			continue
		}

		// When secret type is FILE, it calls SecretGetFileSecret method.
		if strings.ToUpper(secret.SecretType) == "FILE" {
			fileSecretContent, err := secretObj.GetFileSecret(secret, entireSecretPath)
			if err != nil {
				saveLastErr = err
				secretObj.log.Error(err.Error() + "secretPath:" + entireSecretPath)
				continue
			}
			secretDictionary[secretToRetrieve] = fileSecretContent

		} else {
			secretDictionary[secretToRetrieve] = secret.Password
		}
	}

	return secretDictionary, saveLastErr
}

// SecretGetSecretByPath returns secret object for a specific path, title.
func (secretObj *SecretObj) SecretGetSecretByPath(secretPath string, secretTitle string, separator string, endpointPath string) (entities.Secret, error) {

	var body io.ReadCloser
	var technicalError error
	var businessError error
	var scode int

	params := url.Values{}
	params.Add("path", secretPath)
	params.Add("title", secretTitle)
	params.Add("separator", separator)
	params.Add("decrypt", fmt.Sprintf("%v", secretObj.decrypt))

	if secretObj.authenticationObj.ApiVersion != "" {
		params.Add("version", secretObj.authenticationObj.ApiVersion)
	}

	endpointUrl := secretObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	parsedUrl, _ := url.Parse(endpointUrl)
	parsedUrl.RawQuery = params.Encode()

	endpointUrl = parsedUrl.String()

	messageLog := fmt.Sprintf("%v %v", "GET", endpointUrl)
	secretObj.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         endpointUrl,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.SecretGetSecretByPath,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	technicalError = backoff.Retry(func() error {
		body, scode, technicalError, businessError = secretObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.Secret{}, technicalError
	}

	if businessError != nil {
		return entities.Secret{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.Secret{}, err
	}

	SecretObjectList, err := decodeSecretListResponse(bodyBytes)
	if err != nil {
		err = errors.New(err.Error() + ", Ensure Password Safe version is 23.1 or greater.")
		return entities.Secret{}, err
	}

	if len(SecretObjectList) == 0 {
		scode = 404
		err = fmt.Errorf("error %v: StatusCode: %v ", "SecretGetSecretByPath, Secret was not found", scode)
		return entities.Secret{}, err
	}

	return SecretObjectList[0], nil
}

// SecretGetFileSecret call secrets-safe/secrets/<secret_id>/file/download enpoint
// and returns file secret value.
func (secretObj *SecretObj) SecretGetFileSecret(secretId string, endpointPath string) (string, error) {

	var body io.ReadCloser
	var technicalError error
	var businessError error

	url := secretObj.authenticationObj.ApiUrl.JoinPath(endpointPath, secretId, "/file/download").String()

	messageLog := fmt.Sprintf("%v %v", "GET", url)
	secretObj.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         url,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.SecretGetFileSecret,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  secretObj.authenticationObj.ApiVersion,
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = secretObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return "", technicalError
	}

	if businessError != nil {
		return "", businessError
	}

	defer func() { _ = body.Close() }()
	responseData, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	responseString := string(responseData)
	return responseString, nil

}

// CreateSecretFlow is responsible for creating secrets in Password Safe.
// secretDetails accepts either a version-neutral input (SecretCredentialInput,
// SecretTextInput, SecretFileInput) — in which case the matching Config30/Config31
// is selected here based on the authenticated API version — or a Config30/Config31
// directly, which is passed through unchanged for backward compatibility.
func (secretObj *SecretObj) CreateSecretFlow(folderTarget string, secretDetails interface{}) (entities.CreateSecretResponse, error) {

	var folder *entities.FolderResponse
	var createResponse entities.CreateSecretResponse
	var err error

	// Translate version-neutral inputs into the Config30/Config31 the API expects;
	// callers passing Config30/Config31 directly fall through unchanged.
	switch in := secretDetails.(type) {
	case entities.SecretCredentialInput:
		secretDetails, err = buildCredentialSecretConfig(in, secretObj.authenticationObj.ApiVersion)
	case entities.SecretTextInput:
		secretDetails, err = buildTextSecretConfig(in, secretObj.authenticationObj.ApiVersion)
	case entities.SecretFileInput:
		secretDetails, err = buildFileSecretConfig(in, secretObj.authenticationObj.ApiVersion)
	}

	if err != nil {
		return createResponse, err
	}

	err = utils.ValidateData(secretDetails)

	if err != nil {
		return createResponse, err
	}

	folders, err := secretObj.SecretGetFoldersAndSafes("secrets-safe/folders/", constants.SecretGetFolders)

	if err != nil {
		return createResponse, err
	}

	for _, v := range folders {
		if v.Name == strings.TrimSpace(folderTarget) {
			folder = &v
			break
		}
	}

	if folder == nil {
		return createResponse, fmt.Errorf("folder %v was not found in folder list", folderTarget)
	}

	createResponse, err = secretObj.SecretCreateSecret(folder.Id, secretDetails)

	if err != nil {
		return createResponse, err
	}

	return createResponse, nil
}

// buildCredentialSecretConfig selects the credential secret config struct matching apiVersion.
func buildCredentialSecretConfig(in entities.SecretCredentialInput, apiVersion string) (interface{}, error) {
	switch apiVersion {
	case "3.0":
		return entities.SecretCredentialDetailsConfig30{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Username:                in.Username,
			Password:                in.Password,
			OwnerId:                 in.OwnerId,
			OwnerType:               in.OwnerType,
			Owners:                  in.OwnersByOwnerId,
		}, nil
	case "3.1":
		return entities.SecretCredentialDetailsConfig31{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Username:                in.Username,
			Password:                in.Password,
			Owners:                  in.OwnersByGroupId,
		}, nil
	case "3.2":
		return entities.SecretCredentialDetailsConfig32{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Username:                in.Username,
			Password:                in.Password,
			Owners:                  in.OwnersByGroupId,
		}, nil
	}
	return nil, fmt.Errorf("unsupported API version: %v", apiVersion)
}

// buildTextSecretConfig selects the text secret config struct matching apiVersion.
func buildTextSecretConfig(in entities.SecretTextInput, apiVersion string) (interface{}, error) {
	switch apiVersion {
	case "3.0":
		return entities.SecretTextDetailsConfig30{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Text:                    in.Text,
			OwnerId:                 in.OwnerId,
			OwnerType:               in.OwnerType,
			Owners:                  in.OwnersByOwnerId,
		}, nil
	case "3.1":
		return entities.SecretTextDetailsConfig31{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Text:                    in.Text,
			Owners:                  in.OwnersByGroupId,
		}, nil
	case "3.2":
		return entities.SecretTextDetailsConfig32{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			Text:                    in.Text,
			Owners:                  in.OwnersByGroupId,
		}, nil
	}
	return nil, fmt.Errorf("unsupported API version: %v", apiVersion)
}

// buildFileSecretConfig selects the file secret config struct matching apiVersion.
func buildFileSecretConfig(in entities.SecretFileInput, apiVersion string) (interface{}, error) {
	switch apiVersion {
	case "3.0":
		return entities.SecretFileDetailsConfig30{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			FileName:                in.FileName,
			FileContent:             in.FileContent,
			OwnerId:                 in.OwnerId,
			OwnerType:               in.OwnerType,
			Owners:                  in.OwnersByOwnerId,
		}, nil
	case "3.1":
		return entities.SecretFileDetailsConfig31{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			FileName:                in.FileName,
			FileContent:             in.FileContent,
			Owners:                  in.OwnersByGroupId,
		}, nil
	case "3.2":
		return entities.SecretFileDetailsConfig32{
			SecretDetailsBaseConfig: in.SecretDetailsBaseConfig,
			FileName:                in.FileName,
			FileContent:             in.FileContent,
			Owners:                  in.OwnersByGroupId,
		}, nil
	}
	return nil, fmt.Errorf("unsupported API version: %v", apiVersion)
}

// decodeSecretListResponse normalizes the secrets-safe/secrets response shape across API versions.
// v3.0/v3.1 return a bare JSON array; v3.2+ wraps it as {"TotalCount": N, "Data": [...]}.
// Try the wrapper first; if the body is the bare array shape, the struct unmarshal fails
// and we fall through to decode it as a list. Mirrors the TS idiom:
//
//	Array.isArray(data) ? data : data.Data
func decodeSecretListResponse(body []byte) ([]entities.Secret, error) {
	var wrapped entities.SecretListResponse
	if err := json.Unmarshal(body, &wrapped); err == nil {
		return wrapped.Data, nil
	}
	var list []entities.Secret
	err := json.Unmarshal(body, &list)
	return list, err
}

// SecretCreateFileSecret create a secret of type file.
func (secretObj *SecretObj) SecretCreateFileSecret(SecretCreateSecretUrl string, payload string, secretDetails interface{}) (entities.CreateSecretResponse, error) {

	var fileName string
	var fileContent string

	var CreateSecretResponse entities.CreateSecretResponse

	switch fileSecret := secretDetails.(type) {
	case entities.SecretFileDetailsConfig30:
		fileName = fileSecret.FileName
		fileContent = fileSecret.FileContent
	case entities.SecretFileDetailsConfig31:
		fileName = fileSecret.FileName
		fileContent = fileSecret.FileContent
	case entities.SecretFileDetailsConfig32:
		fileName = fileSecret.FileName
		fileContent = fileSecret.FileContent
	}

	body, err := secretObj.authenticationObj.HttpClient.CreateMultiPartRequest(SecretCreateSecretUrl, fileName, []byte(payload), fileContent, secretObj.authenticationObj.ApiVersion)
	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &CreateSecretResponse)

	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	return CreateSecretResponse, nil

}

// SecretCreateSecret calls Secret Safe API Requests enpoint to create secrets in Password Safe.
func (secretObj *SecretObj) SecretCreateSecret(folderId string, secretDetails interface{}) (entities.CreateSecretResponse, error) {

	var CreateSecretResponse entities.CreateSecretResponse
	var secretCredentialDetailsJson string
	var err error

	// Convert object to json string.
	secretDetailsJson, err := json.Marshal(secretDetails)
	if err != nil {
		return CreateSecretResponse, err
	}
	secretCredentialDetailsJson = string(secretDetailsJson)

	payload := string(secretCredentialDetailsJson)

	b := bytes.NewBufferString(payload)

	// path depends on the type of secret (credential, text, file).
	path := secretObj.GetPathToCreateSecret(secretDetails)

	SecretCreateSecretUrl := secretObj.authenticationObj.ApiUrl.JoinPath("secrets-safe/folders", folderId, path).String()

	messageLog := fmt.Sprintf("%v %v", "POST", SecretCreateSecretUrl)
	secretObj.log.Debug(messageLog)

	// file secrets have a special behavior, they need to be created using multipart request.
	if path == "secrets/file" {
		return secretObj.SecretCreateFileSecret(SecretCreateSecretUrl, payload, secretDetails)
	}

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         SecretCreateSecretUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      constants.SecretCreateSecret,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  secretObj.authenticationObj.ApiVersion,
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = secretObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.CreateSecretResponse{}, technicalError
	}

	if businessError != nil {
		return entities.CreateSecretResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &CreateSecretResponse)

	if err != nil {
		secretObj.log.Error(err.Error())
		return entities.CreateSecretResponse{}, err
	}

	return CreateSecretResponse, nil

}

// GetPathToCreateSecret get endpoint path.
func (secretObj *SecretObj) GetPathToCreateSecret(secretDetails interface{}) string {
	// path depends on the type of secret (credential, text, file).
	var path string
	switch secretDetails.(type) {
	case entities.SecretCredentialDetailsConfig30:
		path = "secrets"
	case entities.SecretCredentialDetailsConfig31:
		path = "secrets"
	case entities.SecretCredentialDetailsConfig32:
		path = "secrets"
	case entities.SecretTextDetailsConfig30:
		path = "secrets/text"
	case entities.SecretTextDetailsConfig31:
		path = "secrets/text"
	case entities.SecretTextDetailsConfig32:
		path = "secrets/text"
	case entities.SecretFileDetailsConfig30:
		path = "secrets/file"
	case entities.SecretFileDetailsConfig31:
		path = "secrets/file"
	case entities.SecretFileDetailsConfig32:
		path = "secrets/file"
	}
	return path
}

// SecretGetFoldersFlow get folders list
func (secretObj *SecretObj) SecretGetFoldersListFlow() ([]entities.FolderResponse, error) {
	return secretObj.SecretGetFoldersAndSafes("secrets-safe/folders/", constants.SecretGetFolders)
}

// SecretGetSafesFlow get safes list
func (secretObj *SecretObj) SecretGetSafesListFlow() ([]entities.FolderResponse, error) {
	return secretObj.SecretGetFoldersAndSafes("secrets-safe/safes/", constants.SecretGetSafes)
}

// SecretGetFoldersAndSafes call secrets-safe/folders/ - secrets-safe/folders/  enpoint
// and returns folder list - safe list
func (secretObj *SecretObj) SecretGetFoldersAndSafes(endpointPath string, method string) ([]entities.FolderResponse, error) {
	messageLog := fmt.Sprintf("%v %v", "GET", endpointPath)
	secretObj.log.Debug(messageLog + endpointPath)

	url := secretObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	var foldersObj []entities.FolderResponse

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         url,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.SecretGetFolders,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  secretObj.authenticationObj.ApiVersion,
	}

	response, err := secretObj.authenticationObj.HttpClient.MakeRequest(callSecretSafeAPIObj, secretObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		secretObj.log.Error(err.Error())
		return foldersObj, err
	}

	err = json.Unmarshal(response, &foldersObj)
	if err != nil {
		secretObj.log.Error(err.Error())
		return foldersObj, err
	}

	if len(foldersObj) == 0 {
		return foldersObj, fmt.Errorf("empty List")
	}

	return foldersObj, nil

}

// GetParentFolderId Get parent folder id using folder name.
func (secretObj *SecretObj) GetParentFolderId(folderTarget string) (string, error) {

	var parentFolder *entities.FolderResponse

	if folderTarget == "" {
		return "", fmt.Errorf("parent folder name must not be empty")
	}

	folders, err := secretObj.SecretGetFoldersAndSafes("secrets-safe/folders/", constants.SecretGetFolders)

	if err != nil {
		return "", err
	}

	for _, v := range folders {
		if v.Name == strings.TrimSpace(folderTarget) {
			parentFolder = &v
			break
		}
	}

	if parentFolder == nil {
		return "", fmt.Errorf("folder %v was not found in folder list", folderTarget)
	}

	return parentFolder.Id, nil
}

// CreateFolderFlow is responsible for creating folders/safes in Password Safe.
func (secretObj *SecretObj) CreateFolderFlow(folderTarget string, folderDetails entities.FolderDetails) (entities.CreateFolderResponse, error) {

	var createFolderesponse entities.CreateFolderResponse
	var err error

	if folderDetails.FolderType == "" {
		folderDetails.FolderType = "FOLDER"
	}

	secretObj.log.Debug(fmt.Sprintf("Folder Type: %v", folderDetails.FolderType))

	// if it is folder
	if folderDetails.FolderType == "FOLDER" {
		parentFolderId, err := secretObj.GetParentFolderId(folderTarget)
		if err != nil {
			return createFolderesponse, err
		}
		formattedParentFolderId, _ := uuid.Parse(parentFolderId)
		folderDetails.ParentId = formattedParentFolderId
	}

	err = utils.ValidateData(folderDetails)

	if err != nil {
		return createFolderesponse, err
	}

	createFolderesponse, err = secretObj.SecretCreateFolder(folderDetails)

	if err != nil {
		return createFolderesponse, err
	}

	return createFolderesponse, nil
}

// SecretCreateFolder calls Secret Safe API Requests enpoint to create folders/safes in Password Safe.
func (secretObj *SecretObj) SecretCreateFolder(folderDetails entities.FolderDetails) (entities.CreateFolderResponse, error) {

	path := "secrets-safe/folders/"
	method := constants.SecretCreateFolder

	if folderDetails.FolderType == "SAFE" {
		path = "secrets-safe/safes/"
		method = constants.SecretCreateSafes
	}

	folderCredentialDetailsJson, err := json.Marshal(folderDetails)

	if err != nil {
		return entities.CreateFolderResponse{}, err
	}

	payload := string(folderCredentialDetailsJson)
	b := bytes.NewBufferString(payload)

	var createSecretResponse entities.CreateFolderResponse

	SecretCreateSecretUrl := secretObj.authenticationObj.ApiUrl.JoinPath(path).String()
	messageLog := fmt.Sprintf("%v %v", "POST", SecretCreateSecretUrl)
	secretObj.log.Debug(messageLog)

	var body io.ReadCloser
	var technicalError error
	var businessError error

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         SecretCreateSecretUrl,
		HttpMethod:  "POST",
		Body:        *b,
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  secretObj.authenticationObj.ApiVersion,
	}

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = secretObj.authenticationObj.HttpClient.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, secretObj.authenticationObj.ExponentialBackOff)

	if technicalError != nil {
		return entities.CreateFolderResponse{}, technicalError
	}

	if businessError != nil {
		return entities.CreateFolderResponse{}, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.CreateFolderResponse{}, err
	}

	err = json.Unmarshal([]byte(bodyBytes), &createSecretResponse)

	if err != nil {
		secretObj.log.Error(err.Error())
		return entities.CreateFolderResponse{}, err
	}

	return createSecretResponse, nil

}

// DeleteSecretById deletes a secret by its ID.
func (secretObj *SecretObj) DeleteSecretById(secretID string) error {
	urlBuilder := func(id string) string {
		return secretObj.authenticationObj.ApiUrl.JoinPath("secrets-safe/secrets", id).String()
	}
	return utils.DeleteResourceByID(
		secretID,
		"secret",
		constants.SecretDeleteSecret,
		urlBuilder,
		true, // validate as UUID
		&secretObj.authenticationObj.HttpClient,
		secretObj.authenticationObj.ExponentialBackOff,
		secretObj.log,
	)
}

// DeleteFolderById deletes a folder by its ID.
func (secretObj *SecretObj) DeleteFolderById(folderID string) error {
	urlBuilder := func(id string) string {
		return secretObj.authenticationObj.ApiUrl.JoinPath("secrets-safe/folders", id).String()
	}
	return utils.DeleteResourceByID(
		folderID,
		"folder",
		constants.SecretDeleteFolder,
		urlBuilder,
		true, // validate as UUID
		&secretObj.authenticationObj.HttpClient,
		secretObj.authenticationObj.ExponentialBackOff,
		secretObj.log,
	)
}

// DeleteSafeById deletes a safe by its ID.
func (secretObj *SecretObj) DeleteSafeById(safeID string) error {
	urlBuilder := func(id string) string {
		return secretObj.authenticationObj.ApiUrl.JoinPath("secrets-safe/safes", id).String()
	}
	return utils.DeleteResourceByID(
		safeID,
		"safe",
		constants.SecretDeleteSafe,
		urlBuilder,
		true, // validate as UUID
		&secretObj.authenticationObj.HttpClient,
		secretObj.authenticationObj.ExponentialBackOff,
		secretObj.log,
	)
}

// SearchSecretByTitleFlow calls Password Safe API endpoint to search secrets by title.
func (secretObj *SecretObj) SearchSecretByTitleFlow(secretTitle string) (entities.Secret, error) {
	var secretResponse []entities.Secret
	secretResponse, err := secretObj.SearchSecretByTitle("secrets-safe/secrets", secretTitle)
	if err != nil {
		return entities.Secret{}, err
	}

	if len(secretResponse) > 0 {
		return secretResponse[0], nil
	}
	return entities.Secret{}, fmt.Errorf("secret was not found: %s", secretTitle)
}

// SearchSecretByTitle calls secrets-safe/secrets endpoint
func (secretObj *SecretObj) SearchSecretByTitle(endpointPath string, title string) ([]entities.Secret, error) {

	var secretResponse []entities.Secret

	params := url.Values{}
	params.Add("title", title)
	params.Add("decrypt", fmt.Sprintf("%v", secretObj.decrypt))

	endpointUrl := secretObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	parsedUrl, err := url.Parse(endpointUrl)
	if err != nil {
		return secretResponse, fmt.Errorf("failed to parse endpoint URL: %w", err)
	}

	parsedUrl.RawQuery = params.Encode()

	endpointUrl = parsedUrl.String()

	messageLog := fmt.Sprintf("%v %v", "GET", endpointUrl)
	secretObj.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         endpointUrl,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      constants.SecretGetSecretByTitle,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  "",
	}

	response, err := secretObj.authenticationObj.HttpClient.MakeRequest(callSecretSafeAPIObj, secretObj.authenticationObj.ExponentialBackOff)

	if err != nil {
		return secretResponse, err
	}

	secretResponse, err = decodeSecretListResponse(response)
	if err != nil {
		return nil, err
	}

	return secretResponse, nil
}
