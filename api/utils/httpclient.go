// Copyright 2024 BeyondTrust. All rights reserved.
// utils responsible for utility functions.
package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"

	urlnet "net/url"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/constants"
	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"github.com/cenkalti/backoff/v4"
	"golang.org/x/crypto/pkcs12"
)

// HttpClientObj responsible for http request instance.
type HttpClientObj struct {
	HttpClient *http.Client
	Context    context.Context
	log        logging.Logger
}

// GetHttpClient is responsible for configuring an HTTP client and transport for API calls.
func GetHttpClient(clientTimeOut int, verifyCa bool, certificate string, certificate_key string, logger logging.Logger) (*HttpClientObj, error) {
	var cert tls.Certificate

	if certificate != "" && certificate_key != "" {
		certi, err := tls.X509KeyPair([]byte(certificate), []byte(certificate_key))

		if err != nil {
			logger.Error("issue parsing certificate public/private key pair of PEM encoded data.")
			return nil, err
		}

		cert = certi
	}

	// TSL Config
	var tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: !verifyCa,
			Certificates:       []tls.Certificate{cert},
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		},
	}

	var jar, _ = cookiejar.New(nil)

	// Client
	var client = &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   time.Second * time.Duration(clientTimeOut),
	}

	httpClientObj := &HttpClientObj{
		HttpClient: client,
		log:        logger,
	}

	return httpClientObj, nil
}

// GetPFXContent decrypt pfx certificate.
func GetPFXContent(clientCertificatePath string, clientCertificateName string, clientCertificatePassword string, logger logging.Logger) (string, string, error) {

	if clientCertificateName == "" {
		return "", "", errors.New("empty certificate path")
	}

	pfxFile, err := os.ReadFile(filepath.Join(clientCertificatePath, clientCertificateName))
	if err != nil {
		logger.Error(err.Error())
		return "", "", err
	}

	pfxFileBlock, err := pkcs12.ToPEM(pfxFile, clientCertificatePassword)
	if err != nil {
		logger.Error(err.Error())
		return "", "", err
	}

	var keyBlock, certificateBlock *pem.Block
	for _, pemBlock := range pfxFileBlock {
		switch pemBlock.Type {
		case "PRIVATE KEY":
			keyBlock = pemBlock
		case "CERTIFICATE":
			certificateBlock = pemBlock
		}
	}

	if keyBlock == nil {
		err = errors.New("error getting Key Block")
		logger.Error(err.Error())
		return "", "", err
	}
	if certificateBlock == nil {
		err = errors.New("error getting Certificate Block")
		logger.Error(err.Error())
		return "", "", err
	}

	privateKeyData := pem.EncodeToMemory(keyBlock)
	certData := pem.EncodeToMemory(certificateBlock)

	return string(certData), string(privateKeyData), nil
}

// CallSecretSafeAPI prepares http call
//func (client *HttpClientObj) CallSecretSafeAPI(url string, httpMethod string, body bytes.Buffer, method string, accessToken string, apiKey string, contentType string) (io.ReadCloser, int, error, error) {

func (client *HttpClientObj) CallSecretSafeAPI(callSecretSafeAPIObj entities.CallSecretSafeAPIObj) (io.ReadCloser, int, error, error) {

	response, scode, technicalError, businessError := client.HttpRequest(callSecretSafeAPIObj.Url,
		callSecretSafeAPIObj.HttpMethod,
		callSecretSafeAPIObj.Body,
		callSecretSafeAPIObj.AccessToken,
		callSecretSafeAPIObj.ApiKey,
		callSecretSafeAPIObj.ContentType,
		callSecretSafeAPIObj.ApiVersion,
	)

	if technicalError != nil {
		messageLog := fmt.Sprintf("Error in %s %s \n", callSecretSafeAPIObj.Method, technicalError.Error())
		client.log.Error(messageLog)
	}

	if businessError != nil {
		messageLog := fmt.Sprintf("Error in %s: %s \n", callSecretSafeAPIObj.Method, businessError.Error())
		client.log.Debug(messageLog)
	}
	return response, scode, technicalError, businessError
}

// GetAuthorizationHeader Get authorization header string
func (client *HttpClientObj) GetAuthorizationHeader(accessToken string, apiKey string) string {

	var authorizationHeader string

	if accessToken != "" {
		authorizationHeader = "Bearer " + accessToken
	}

	if apiKey != "" {
		authorizationHeader = "PS-Auth key=" + apiKey
	}

	return authorizationHeader
}

// SetApiVersion Set API Version to URL.
func (client *HttpClientObj) SetApiVersion(url string, apiVersion string) string {

	// Append API Version to URL
	if apiVersion != "" {
		params := urlnet.Values{}
		params.Add("version", apiVersion)

		parsedUrl, _ := urlnet.Parse(url)
		parsedUrl.RawQuery = params.Encode()

		url = parsedUrl.String()
	}

	return url
}

// resolveContext returns ctx if non-nil, otherwise context.Background().
func resolveContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// handleDoError builds the appropriate return values when http.Client.Do returns an error.
func (client *HttpClientObj) handleDoError(resp *http.Response, err error) (io.ReadCloser, int, error, error) {
	client.log.Debug(fmt.Sprintf("%v %v", "Error Making request: ", err.Error()))
	if resp != nil {
		return nil, resp.StatusCode, err, nil
	}
	return nil, 0, err, nil
}

// handleResponseStatus inspects resp.StatusCode and returns the appropriate values.
func (client *HttpClientObj) handleResponseStatus(resp *http.Response, method string, body bytes.Buffer) (io.ReadCloser, int, error, error) {
	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusRequestTimeout {
		_ = resp.Body.Close()
		err := fmt.Errorf("error %s: StatusCode: %d, Status: %s, Body: %s", method, resp.StatusCode, resp.Status, body.String())
		client.log.Error(err.Error())
		return nil, resp.StatusCode, err, nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		respBody := new(bytes.Buffer)
		_, err := respBody.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			client.log.Error(err.Error())
			return nil, resp.StatusCode, err, nil
		}
		return nil, resp.StatusCode, nil, fmt.Errorf("error - status code: %v - %v", resp.StatusCode, respBody)
	}
	return resp.Body, resp.StatusCode, nil, nil
}

// RedactSensitiveURL masks sensitive path components (such as credential
// request IDs) so they never appear in clear text in log output. The request
// ID is the short-lived token that, presented to GET /Credentials/{requestId},
// returns a plaintext managed-account password, so it must be redacted at every
// log emission point.
func RedactSensitiveURL(rawURL string) string {
	parsedUrl, err := urlnet.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	escapedPath := parsedUrl.EscapedPath()
	segments := strings.Split(escapedPath, "/")
	redacted := false
	for i, segment := range segments {
		// .../Credentials/<requestId> and .../Requests/<requestId>/checkin
		// carry the sensitive request ID in the segment immediately
		// following the resource name.
		switch strings.ToLower(segment) {
		case "credentials", "requests":
			if i+1 < len(segments) && segments[i+1] != "" {
				segments[i+1] = "****"
				redacted = true
			}
		}
	}

	if !redacted {
		return rawURL
	}

	// Swap the original path for the redacted one in place so the rest of
	// the URL (scheme, host, query string) is preserved exactly and the
	// "****" mask is not percent-encoded.
	return strings.Replace(rawURL, escapedPath, strings.Join(segments, "/"), 1)
}

// HttpRequest makes http request to the server.
func (client *HttpClientObj) HttpRequest(url string, method string, body bytes.Buffer, accessToken string, apiKey string, contentType string, apiVersion string) (io.ReadCloser, int, error, error) {
	url = client.SetApiVersion(url, apiVersion)
	client.log.Debug(fmt.Sprintf("Entire URL: %s", RedactSensitiveURL(url)))

	req, err := http.NewRequestWithContext(resolveContext(client.Context), method, url, &body)
	if err != nil {
		return nil, 0, err, nil
	}
	req.Header = http.Header{"Content-Type": []string{contentType}}

	if authorizationHeader := client.GetAuthorizationHeader(accessToken, apiKey); authorizationHeader != "" {
		req.Header.Set("Authorization", authorizationHeader)
	}

	resp, err := client.HttpClient.Do(req)
	if err != nil {
		return client.handleDoError(resp, err)
	}
	return client.handleResponseStatus(resp, method, body)
}

// CreateMultipartRequest creates and sends multipart request.
func (client *HttpClientObj) CreateMultiPartRequest(url, fileName string, metadata []byte, fileContent string, apiVersion string) (io.ReadCloser, error) {

	var requestBody bytes.Buffer

	multipartWriter := multipart.NewWriter(&requestBody)

	err := multipartWriter.WriteField("secretmetadata", string(metadata))
	if err != nil {
		return nil, err
	}

	fileWriter, err := multipartWriter.CreateFormFile("file", fileName)
	if err != nil {
		return nil, err
	}

	fileReader := strings.NewReader(fileContent)

	_, err = io.Copy(fileWriter, fileReader)
	if err != nil {
		return nil, err
	}

	err = multipartWriter.Close()
	if err != nil {
		return nil, err
	}

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		ApiVersion:  apiVersion,
		Url:         url,
		HttpMethod:  "POST",
		Body:        requestBody,
		Method:      constants.CreateMultiPartRequest,
		AccessToken: "",
		ApiKey:      "",
		ContentType: multipartWriter.FormDataContentType(),
	}

	body, _, technicalError, businessError := client.CallSecretSafeAPI(*callSecretSafeAPIObj)

	if technicalError != nil {
		return body, technicalError
	}

	if businessError != nil {
		return body, businessError
	}

	return body, nil
}

// MakeRequest Make http request to API.
func (client *HttpClientObj) MakeRequest(callSecretSafeAPIObj *entities.CallSecretSafeAPIObj, exponentialBackOff *backoff.ExponentialBackOff) ([]byte, error) {

	var body io.ReadCloser
	var technicalError error
	var businessError error

	technicalError = backoff.Retry(func() error {
		body, _, technicalError, businessError = client.CallSecretSafeAPI(*callSecretSafeAPIObj)
		return technicalError
	}, exponentialBackOff)

	if technicalError != nil {
		return nil, technicalError
	}

	if businessError != nil {
		return nil, businessError
	}

	defer func() { _ = body.Close() }()
	bodyBytes, err := io.ReadAll(body)

	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// GetGeneralList get list for any module.
func (client *HttpClientObj) GetGeneralList(url string, apiVersion string, method string, exponentialBackOff *backoff.ExponentialBackOff) ([]byte, error) {

	callSecretSafeAPIObj := &entities.CallSecretSafeAPIObj{
		Url:         url,
		HttpMethod:  "GET",
		Body:        bytes.Buffer{},
		Method:      method,
		AccessToken: "",
		ApiKey:      "",
		ContentType: "application/json",
		ApiVersion:  apiVersion,
	}

	response, err := client.MakeRequest(callSecretSafeAPIObj, exponentialBackOff)

	if err != nil {
		return nil, err
	}

	return response, nil

}
