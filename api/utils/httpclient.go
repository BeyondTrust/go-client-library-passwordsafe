// Copyright 2024 BeyondTrust. All rights reserved.
// utils responsible for utility functions.
package utils

import (
	"bytes"
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

	logging "github.com/BeyondTrust/go-client-library-passwordsafe/api/logging"
	"golang.org/x/crypto/pkcs12"
)

// HttpClientObj responsible for http request instance.
type HttpClientObj struct {
	HttpClient *http.Client
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

func GetPFXContent(clientCertificatePath string, clientCertificateName string, clientCertificatePassword string, logger logging.Logger) (string, string, error) {

	if clientCertificateName != "" {
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
			if pemBlock.Type == "PRIVATE KEY" {
				keyBlock = pemBlock
			} else if pemBlock.Type == "CERTIFICATE" {
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

	return "", "", errors.New("empty certificate path")

}

// CallSecretSafeAPI prepares http call
func (client *HttpClientObj) CallSecretSafeAPI(url string, httpMethod string, body bytes.Buffer, method string, accesToken string, apiKey string, contentType string) (io.ReadCloser, int, error, error) {
	response, scode, technicalError, businessError := client.HttpRequest(url, httpMethod, body, accesToken, apiKey, contentType)
	if technicalError != nil {
		messageLog := fmt.Sprintf("Error in %v %v \n", method, technicalError)
		client.log.Error(messageLog)
	}

	if businessError != nil {
		messageLog := fmt.Sprintf("Error in %v: %v \n", method, businessError)
		client.log.Debug(messageLog)
	}
	return response, scode, technicalError, businessError
}

// HttpRequest makes http request to the server.
func (client *HttpClientObj) HttpRequest(url string, method string, body bytes.Buffer, accesToken string, apiKey string, contentType string) (closer io.ReadCloser, scode int, technicalError error, businessError error) {

	req, err := http.NewRequest(method, url, &body)
	if err != nil {
		return nil, 0, err, nil
	}
	req.Header = http.Header{"Content-Type": []string{contentType}}

	if accesToken != "" {
		req.Header.Set("Authorization", "Bearer "+accesToken)
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "PS-Auth key="+apiKey)
	}

	resp, err := client.HttpClient.Do(req)
	if err != nil {
		client.log.Error(fmt.Sprintf("%v %v", "Error Making request: ", err.Error()))
		return nil, resp.StatusCode, err, nil
	}

	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusRequestTimeout {
		err = fmt.Errorf("error %v: StatusCode: %v, %v, %v", method, scode, err, body)
		client.log.Error(err.Error())
		return nil, resp.StatusCode, err, nil
	}

	if resp.StatusCode >= http.StatusBadRequest {
		respBody := new(bytes.Buffer)
		_, err = respBody.ReadFrom(resp.Body)
		if err != nil {
			client.log.Error(err.Error())
			return nil, resp.StatusCode, err, nil
		}

		err = fmt.Errorf("error - status code: %v - %v", resp.StatusCode, respBody)
		return nil, resp.StatusCode, nil, err
	}

	return resp.Body, resp.StatusCode, nil, nil
}

// CreateMultipartRequest creates and sends multipart request.
func (client *HttpClientObj) CreateMultiPartRequest(url, fileName string, metadata []byte, fileContent string) (io.ReadCloser, error) {

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

	multipartWriter.Close()

	body, _, technicalError, businessError := client.CallSecretSafeAPI(url, "POST", requestBody, "CreateMultiPartRequest", "", "", multipartWriter.FormDataContentType())

	if technicalError != nil {
		return body, technicalError
	}

	if businessError != nil {
		return body, businessError
	}

	return body, nil
}
