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

package caclient

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"net/http"

	"github.com/pkg/errors"

	jsoniter "encoding/json"
	"github.com/ztalab/zaca-sdk/signature"
)

var revokePath = "/api/v1/cfssl/revoke"

// This type is meant to be unmarshalled from JSON
type RevokeRequest struct {
	Serial  string `json:"serial"`
	AKI     string `json:"authority_key_id"`
	Reason  string `json:"reason"`
	Nonce   string `json:"nonce"`
	Sign    string `json:"sign"`
	AuthKey string `json:"auth_key"`
	Profile string `json:"profile"`
}

// RevokeItSelf Revoke one's own certificate
func (ex *Exchanger) RevokeItSelf() error {
	tlsCert, err := ex.Transport.GetCertificate()
	if err != nil {
		return err
	}
	cert := tlsCert.Leaf
	priv := tlsCert.PrivateKey

	if err := revokeCert(ex.caAddr, priv, cert); err != nil {
		return err
	}
	ex.logger.With("sn", cert.SerialNumber.String()).Info("Service offline revoking its own certificate")

	return nil
}

func (cai *CAInstance) RevokeCert(priv crypto.PublicKey, cert *x509.Certificate) error {
	return revokeCert(cai.CaAddr, priv, cert)
}

func revokeCert(caAddr string, priv crypto.PublicKey, cert *x509.Certificate) error {
	s := signature.NewSigner(priv)

	nonce := cert.SerialNumber.String()

	sign, err := s.Sign([]byte(nonce))
	if err != nil {
		return err
	}

	req := &RevokeRequest{
		Serial: cert.SerialNumber.String(),
		AKI:    hex.EncodeToString(cert.AuthorityKeyId),
		Reason: "",
		Nonce:  nonce,
		Sign:   sign,
	}

	reqBytes, _ := jsoniter.Marshal(req)

	buf := bytes.NewBuffer(reqBytes)

	resp, err := httpClient.Post(caAddr+revokePath, "application/json", buf)
	if err != nil {
		return errors.Wrap(err, "Request error")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("Request error")
	}

	return nil
}
