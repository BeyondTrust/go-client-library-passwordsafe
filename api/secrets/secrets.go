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

	urlnet "net/url"
)

// SecretObj responsible for session requests.
type SecretObj struct {
	log                    logging.Logger
	authenticationObj      authentication.AuthenticationObj
	maxFileSecretSizeBytes int
}

// NewSecretObj creates secret obj
func NewSecretObj(authentication authentication.AuthenticationObj, logger logging.Logger, maxFileSecretSizeBytes int) (*SecretObj, error) {
	secretObj := &SecretObj{
		log:                    logger,
		authenticationObj:      authentication,
		maxFileSecretSizeBytes: maxFileSecretSizeBytes,
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

	if secretObj.authenticationObj.ApiVersion != "" {
		params.Add("version", secretObj.authenticationObj.ApiVersion)
	}

	url := secretObj.authenticationObj.ApiUrl.JoinPath(endpointPath).String()

	parsedUrl, _ := urlnet.Parse(url)
	parsedUrl.RawQuery = params.Encode()

	url = parsedUrl.String()

	messageLog := fmt.Sprintf("%v %v", "GET", url)
	secretObj.log.Debug(messageLog)

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         url,
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

	defer body.Close()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return entities.Secret{}, err
	}

	var SecretObjectList []entities.Secret
	err = json.Unmarshal([]byte(bodyBytes), &SecretObjectList)
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

	defer body.Close()
	responseData, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	responseString := string(responseData)
	return responseString, nil

}

// CreateSecretCredentialFlow is responsible for creating secrets in Password Safe.
func (secretObj *SecretObj) CreateSecretFlow(folderTarget string, secretDetails interface{}) (entities.CreateSecretResponse, error) {

	var folder *entities.FolderResponse
	var createResponse entities.CreateSecretResponse

	err := utils.ValidateData(secretDetails)

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

	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	createResponse, err = secretObj.SecretCreateSecret(folder.Id, secretDetails)

	if err != nil {
		return createResponse, err
	}

	return createResponse, nil
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
	}

	body, err := secretObj.authenticationObj.HttpClient.CreateMultiPartRequest(SecretCreateSecretUrl, fileName, []byte(payload), fileContent, secretObj.authenticationObj.ApiVersion)
	if err != nil {
		return entities.CreateSecretResponse{}, err
	}

	defer body.Close()
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

	defer body.Close()
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
	case entities.SecretTextDetailsConfig30:
		path = "secrets/text"
	case entities.SecretTextDetailsConfig31:
		path = "secrets/text"
	case entities.SecretFileDetailsConfig30:
		path = "secrets/file"
	case entities.SecretFileDetailsConfig31:
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

	defer body.Close()
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
