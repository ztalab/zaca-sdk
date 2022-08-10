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
	"github.com/ztalab/zaca-sdk/pkg/logger"
	"time"

	"github.com/ztalab/cfssl/csr"
	"github.com/ztalab/cfssl/transport/core"
	"github.com/ztalab/zaca-sdk/keygen"
	"go.uber.org/zap"
)

// Role ...
type Role string

const (
	// RoleDefault ...
	RoleDefault Role = "default"
	// RoleIntermediate ...
	RoleIntermediate Role = "intermediate"
)

// Conf ...
type Conf struct {
	CFIdentity  *core.Identity
	DiskStore   bool
	CaAddr      string
	OcspAddr    string
	RotateAfter time.Duration
	Logger      *zap.Logger
	CSRConf     keygen.CSRConf
}

// OptionFunc ...
type OptionFunc func(*Conf)

// NewCAI ...
func NewCAI(opts ...OptionFunc) *CAInstance {
	conf := &defaultConf
	for _, opt := range opts {
		opt(conf)
	}
	conf.Logger.Sugar().Debugf("cai conf: %v", conf)
	//cflog.Logger = conf.Logger.Named("cfssl")
	return &CAInstance{
		Conf: *conf,
	}
}

// CAInstance ...
type CAInstance struct {
	Conf
}

// WithCAServer ...
func WithCAServer(role Role, addr string) OptionFunc {
	return func(c *Conf) {
		c.CaAddr = addr
		c.CFIdentity.Roots = append(c.CFIdentity.Roots, &core.Root{
			Type: "cfssl",
			Metadata: map[string]string{
				"host":    addr,
				"profile": string(role),
			},
		})
		c.CFIdentity.ClientRoots = append(c.CFIdentity.ClientRoots, &core.Root{
			Type: "cfssl",
			Metadata: map[string]string{
				"host":    addr,
				"profile": string(role),
			},
		})
		c.CFIdentity.Profiles["cfssl"]["remote"] = addr
		c.CFIdentity.Profiles["cfssl"]["profile"] = string(role)
	}
}

func WithOcspAddr(ocspAttr string) OptionFunc {
	return func(c *Conf) {
		c.OcspAddr = ocspAttr
	}
}

func WithAuthKey(key string) OptionFunc {
	return func(c *Conf) {
		c.CFIdentity.Profiles["cfssl"]["auth-type"] = "standard"
		c.CFIdentity.Profiles["cfssl"]["auth-key"] = key
	}
}

func WithRotateAfter(du time.Duration) OptionFunc {
	return func(c *Conf) {
		c.RotateAfter = du
	}
}

func WithLogger(l *zap.Logger) OptionFunc {
	return func(c *Conf) {
		c.Logger = l
	}
}

func WithCSRConf(csrConf keygen.CSRConf) OptionFunc {
	return func(c *Conf) {
		c.CSRConf = csrConf
	}
}

var defaultConf = Conf{
	CFIdentity: &core.Identity{
		Request:     &csr.CertificateRequest{},
		Roots:       []*core.Root{},
		ClientRoots: []*core.Root{},
		Profiles: map[string]map[string]string{
			"cfssl": make(map[string]string),
		},
	},
	RotateAfter: 5 * time.Minute,
	Logger:      logger.N().Named("cai"),
}
