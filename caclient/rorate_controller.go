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
	"time"

	"github.com/ztalab/cfssl/transport/roots"
	"go.uber.org/zap"
)

// RotateController ...
type RotateController struct {
	transport   *Transport
	rotateAfter time.Duration
	logger      *zap.SugaredLogger
}

// Run ...
func (rc *RotateController) Run() {
	log := rc.logger
	ticker := time.NewTicker(60 * time.Minute)
	defer func() {
		ticker.Stop()
	}()
	for {
		select {
		case <-ticker.C:
			// Automatically update certificates
			err := rc.transport.AutoUpdate()
			if err != nil {
				log.Errorf("Certificate rotation failed: %v", err)
			}
			rc.AddCert()
		}
	}
}

func (rc *RotateController) AddCert() {
	log := rc.logger
	store, err := roots.New(rc.transport.Identity.Roots)
	if err != nil {
		log.Errorf("Failed to get roots: %v", err)
		return
	}
	rc.transport.TrustStore.AddCerts(store.Certificates())

	if len(rc.transport.Identity.ClientRoots) > 0 {
		store, err = roots.New(rc.transport.Identity.ClientRoots)
		if err != nil {
			log.Errorf("Failed to get client roots: %v", err)
			return
		}
		rc.transport.ClientTrustStore.AddCerts(store.Certificates())
	}
	return
}
