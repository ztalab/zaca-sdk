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
	"crypto/x509"
	"encoding/hex"
	"math"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"

	"github.com/ztalab/zaca-sdk/pkg/memorycacher"
	"go.uber.org/zap"
)

var _ OcspClient = &ocspMemCache{}

// ocspMemCache ...
type ocspMemCache struct {
	cache   *memorycacher.Cache
	logger  *zap.SugaredLogger
	ocspURL string // ca server + /ocsp
}

// NewOcspMemCache ...
func NewOcspMemCache(logger *zap.SugaredLogger, ocspAddr string) (OcspClient, error) {
	return &ocspMemCache{
		cache:   memorycacher.New(30*time.Minute, memorycacher.NoExpiration, math.MaxInt64),
		logger:  logger,
		ocspURL: ocspAddr,
	}, nil
}

// Validate ...
func (of *ocspMemCache) Validate(leaf, issuer *x509.Certificate) (bool, error) {
	if atomic.LoadInt64(&ocspBlockSign) == 1 {
		return false, errors.New("ocsp Request disabled")
	}
	if leaf == nil || issuer == nil {
		return false, errors.New("leaf/issuer Missing parameter")
	}
	lo := of.logger.With("sn", leaf.SerialNumber.String(), "aki", hex.EncodeToString(leaf.AuthorityKeyId), "id", leaf.URIs[0])
	// Cache fetch
	if _, ok := of.cache.Get(leaf.SerialNumber.String()); ok {
		return true, nil
	}
	ocspRequest, err := ocsp.CreateRequest(leaf, issuer, &ocspOpts)
	if err != nil {
		lo.Errorf("ocsp req create err: %s", err)
		return false, errors.Wrap(err, "ocsp req Creation failed")
	}
	getOcspFunc := func() (interface{}, error) {
		return SendOcspRequest(of.ocspURL, ocspRequest, leaf, issuer)
	}
	sgValue, err, _ := sg.Do("ocsp"+leaf.SerialNumber.String(), getOcspFunc)
	if err != nil {
		lo.Errorf("ocsp Request error: %v", err)
		// Here, the authentication fails due to CA server. The request is allowed. Try again next time
		return true, errors.Wrap(err, "ocsp Request error")
	}
	ocspResp, ok := sgValue.(*ocsp.Response)
	if !ok {
		lo.Error("single flight Parsing error")
		return false, errors.New("single flight Parsing error")
	}
	lo.Debugf("Verify OCSP and the results: %v", ocspResp.Status)
	if ocspResp.Status == int(ocsp.Success) {
		of.cache.SetDefault(leaf.SerialNumber.String(), true)
		return true, nil
	}
	lo.Warnf("Certificate OCSP validation invalid")
	return false, errors.New("ocsp Authentication failed and the certificate was revoked")
}

func (of *ocspMemCache) Reset() {
	of.cache.Flush()
}
