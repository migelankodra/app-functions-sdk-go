//
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package transforms

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/migelankodra/app-functions-sdk-go/pkg/util"

	"github.com/edgexfoundry/go-mod-core-contracts/clients"
	"github.com/migelankodra/app-functions-sdk-go/appcontext"
)

// HTTPSender ...
type HTTPSender struct {
	URL              string
	MimeType         string
	PersistOnError   bool
	SecretHeaderName string
	SecretPath       string
	CertFile         string
	KeyFile          string
	CAFile           string
}

// NewHTTPSender creates, initializes and returns a new instance of HTTPSender
func NewHTTPSender(url string, mimeType string, persistOnError bool) HTTPSender {
	return HTTPSender{
		URL:            url,
		MimeType:       mimeType,
		PersistOnError: persistOnError,
	}
}
func NewHTTPSenderWithSecretHeader(url string, mimeType string, persistOnError bool, httpHeaderSecretName string, secretPath string) HTTPSender {
	return HTTPSender{
		URL:              url,
		MimeType:         mimeType,
		PersistOnError:   persistOnError,
		SecretHeaderName: httpHeaderSecretName,
		SecretPath:       secretPath,
	}
}

// NewHTTPSSender creates, initializes and returns a new instance of HTTPSender
func NewHTTPSSender(url string, mimeType string, persistOnError bool, certfile string, keyfile string, cafile string) HTTPSender {
	return HTTPSender{
		URL:            url,
		MimeType:       mimeType,
		PersistOnError: persistOnError,
		CertFile:       certfile,
		KeyFile:        keyfile,
		CAFile:         cafile,
	}
}

// HTTPPost will send data from the previous function to the specified Endpoint via http POST.
// If no previous function exists, then the event that triggered the pipeline will be used.
// An empty string for the mimetype will default to application/json.
func (sender HTTPSender) HTTPPost(edgexcontext *appcontext.Context, params ...interface{}) (bool, interface{}) {
	if len(params) < 1 {
		// We didn't receive a result
		return false, errors.New("No Data Received")
	}

	if sender.MimeType == "" {
		sender.MimeType = "application/json"
	}

	exportData, err := util.CoerceType(params[0])
	if err != nil {
		return false, err
	}

	usingSecrets, err := sender.determineIfUsingSecrets()
	if err != nil {
		return false, err
	}

	usingHTTPS, err := sender.determineIfUsingHTTPS()
	if err != nil {
		return false, err
	}

	fmt.Println("usingHTTPS", usingHTTPS)

	var client *http.Client

	if usingHTTPS {
		// load client certificate
		fmt.Println("Loading Certificate ...")
		cert, err := tls.LoadX509KeyPair(sender.CertFile, sender.KeyFile)
		if err != nil {
			return false, err
		}

		fmt.Println("Sender Public Certificate", sender.CertFile)

		// load CA certificate
		fmt.Println("Loading CA Certificate")
		caCert, err := ioutil.ReadFile(sender.CAFile)
		if err != nil {
			return false, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		fmt.Println("CA Public Certificate", sender.CAFile)

		// setup HTTPS client
		fmt.Println("configuring tlsConfiguration")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
		}

		fmt.Println("CA Cert Pool", caCertPool)

		tlsConfig.BuildNameToCertificate()
		fmt.Println("Configuring transport...")
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
		fmt.Println("Client", client)
	} else {
		client = &http.Client{}
	}

	req, err := http.NewRequest(http.MethodPost, sender.URL, bytes.NewReader(exportData))
	if err != nil {
		return false, err
	}
	var theSecrets map[string]string
	if usingSecrets {
		theSecrets, err = edgexcontext.GetSecrets(sender.SecretPath, sender.SecretHeaderName)
		if err != nil {
			return false, err
		}
		req.Header.Set(sender.SecretHeaderName, theSecrets[sender.SecretHeaderName])
	}

	fmt.Println("Content-Type ", sender.MimeType)
	req.Header.Set("Content-Type", sender.MimeType)

	edgexcontext.LoggingClient.Info("POSTing data")
	fmt.Println("POSTing data")
	response, err := client.Do(req)
	if err != nil {
		fmt.Println("Response: ", response)
		sender.setRetryData(edgexcontext, exportData)
		return false, err
	}
	defer response.Body.Close()
	edgexcontext.LoggingClient.Info(fmt.Sprintf("Response: %s", response.Status))
	fmt.Println("Response: ", response.Status)
	edgexcontext.LoggingClient.Info(fmt.Sprintf("Sent data: %s", string(exportData)))
	fmt.Println("Sent data: ", string(exportData))
	bodyBytes, errReadingBody := ioutil.ReadAll(response.Body)
	if errReadingBody != nil {
		sender.setRetryData(edgexcontext, exportData)
		return false, errReadingBody
	}

	edgexcontext.LoggingClient.Trace("Data exported", "Transport", "HTTP", clients.CorrelationHeader, edgexcontext.CorrelationID)
	fmt.Println("Data exported", "Transport", "HTTP", clients.CorrelationHeader, edgexcontext.CorrelationID)

	fmt.Println(response.StatusCode)

	// continues the pipeline if we get a 2xx response, stops pipeline if non-2xx response
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		sender.setRetryData(edgexcontext, exportData)
		return false, fmt.Errorf("export failed with %d HTTP status code", response.StatusCode)
	}

	return true, bodyBytes

}
func (sender HTTPSender) determineIfUsingSecrets() (bool, error) {
	//check if one field but not others are provided for secrets
	if sender.SecretPath != "" && sender.SecretHeaderName == "" {
		return false, errors.New("SecretPath was specified but no header name was provided")
	}
	if sender.SecretHeaderName != "" && sender.SecretPath == "" {
		return false, errors.New("HTTP Header Secret Name was provided but no SecretPath was provided")
	}

	// not using secrets if both are blank
	if sender.SecretHeaderName == "" && sender.SecretPath == "" {
		return false, nil
	}
	// using secrets, all required fields are provided
	return true, nil

}

func (sender HTTPSender) determineIfUsingHTTPS() (bool, error) {
	// Check if one field but not others are provided for https
	if sender.CertFile != "" && sender.KeyFile == "" {
		return false, errors.New("Client certificate was specified but not the client private key")
	} else if sender.CertFile == "" && sender.KeyFile != "" {
		return false, errors.New("Client private key was specified but not the client public certificate")
	} else if sender.CertFile != "" && sender.KeyFile != "" && sender.CAFile == "" {
		return false, errors.New("CA public certificate was not specified")
	}

	// If not specified, not using HTTPS
	if sender.CertFile == "" && sender.KeyFile == "" && sender.CAFile == "" {
		return false, nil
	}

	return true, nil
}

func (sender HTTPSender) setRetryData(ctx *appcontext.Context, exportData []byte) {
	if sender.PersistOnError {
		ctx.RetryData = exportData
	}
}
