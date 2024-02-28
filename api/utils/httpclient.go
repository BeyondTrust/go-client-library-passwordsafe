// Copyright 2024 BeyondTrust. All rights reserved.
// utils responsible for utility functions.
package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	logging "go-client-library-passwordsafe/api/logging"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
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

// CallSecretSafeAPI prepares http call
func (client *HttpClientObj) CallSecretSafeAPI(url string, httpMethod string, body bytes.Buffer, method string, accesToken string) (io.ReadCloser, error, error, int) {
	response, technicalError, businessError, scode := client.HttpRequest(url, httpMethod, body, accesToken)
	if technicalError != nil {
		messageLog := fmt.Sprintf("Error in %v %v \n", method, technicalError)
		client.log.Error(messageLog)
	}

	if businessError != nil {
		messageLog := fmt.Sprintf("Error in %v: %v \n", method, businessError)
		client.log.Debug(messageLog)
	}
	return response, technicalError, businessError, scode
}

// HttpRequest makes http request to the server.
func (client *HttpClientObj) HttpRequest(url string, method string, body bytes.Buffer, accesToken string) (closer io.ReadCloser, technicalError error, businessError error, scode int) {

	req, err := http.NewRequest(method, url, &body)
	if err != nil {
		return nil, err, nil, 0
	}
	req.Header = http.Header{
		"Content-Type": {"application/json"},
	}

	if accesToken != "" {
		req.Header.Set("Authorization", "Bearer "+accesToken)
	}

	resp, err := client.HttpClient.Do(req)
	if err != nil {
		client.log.Error(fmt.Sprintf("%v %v", "Error Making request: ", err.Error()))
		return nil, err, nil, 0
	}

	if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusRequestTimeout {
		err = fmt.Errorf("error %v: StatusCode: %v, %v, %v", method, scode, err, body)
		client.log.Error(err.Error())
		return nil, err, nil, resp.StatusCode
	}

	if resp.StatusCode > http.StatusBadRequest {
		respBody := new(bytes.Buffer)
		_, err = respBody.ReadFrom(resp.Body)
		if err != nil {
			client.log.Error(err.Error())
			return nil, err, nil, 0
		}

		err = fmt.Errorf("error - status code: %v - %v", resp.StatusCode, respBody)
		return nil, nil, err, resp.StatusCode
	}

	return resp.Body, nil, nil, resp.StatusCode
}
