/*
Copyright 2022-present The Ztalab Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/ztalab/cfssl/helpers"
	"github.com/ztalab/zaca-sdk/caclient"
	"github.com/ztalab/zaca-sdk/pkg/logger"
)

func ExtractCertFromExchanger(ex *caclient.Exchanger) {
	logger := logger.Named("keypair-exporter")
	tlsCert, err := ex.Transport.GetCertificate()
	if err != nil {
		logger.Errorf("TLS Certificate acquisition failed: %v", err)
		return
	}
	cert := helpers.EncodeCertificatePEM(tlsCert.Leaf)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		logger.Errorf("TLS certificate private key acquisition failed: %v", err)
		return
	}

	key := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	trustCerts := ex.Transport.TrustStore.Certificates()
	caCerts := make([][]byte, 0, len(trustCerts))

	fmt.Println("--- CA Certificate Stared ---")
	for _, caCert := range trustCerts {
		caCertBytes := helpers.EncodeCertificatePEM(caCert)
		caCerts = append(caCerts, caCertBytes)
		fmt.Println("---\n", string(caCertBytes), "\n---")
	}
	fmt.Println("--- CA Certificate End ---")
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println()

	fmt.Println("--- Private key Stared ---\n", string(key), "\n--- Private key End ---")
	fmt.Println("--- Certificate Stared ---\n", string(cert), "\n--- Certificate End ---")
}
