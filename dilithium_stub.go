// Copyright (C) 2020, ISARA Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// <a href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</a>
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !cgo

package iqrcrypto

import (
	"crypto"
	"errors"
	"io"
)

type IqrDilithiumVariant struct{}

var IqrDILITHIUM128 = &IqrDilithiumVariant{}
var IqrDILITHIUM160 = &IqrDilithiumVariant{}

// DilithiumPrivateKey Stub
type DilithiumPrivateKey struct {
}

// Public
func (priv *DilithiumPrivateKey) Public() crypto.PublicKey {
	return errors.New("Built without ISARA Toolkit")
}

// Sign
func (priv *DilithiumPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("Built without ISARA Toolkit")
}

// Destroy
func (priv *DilithiumPrivateKey) Destroy() error {
	return errors.New("Built without ISARA Toolkit")
}

// QSKeyType
func (priv *DilithiumPrivateKey) QSKeyType() string {
	return ""
}

// GenerateDilithiumPrivateKey Stub
func GenerateDilithiumPrivateKey(variant *IqrDilithiumVariant, rand io.Reader) (*DilithiumPrivateKey, error) {
	return nil, errors.New("Built without ISARA Toolkit")
}

// IqrDilithiumExportPrivateKeyPKCS8
func IqrDilithiumExportPrivateKeyPKCS8(key *DilithiumPrivateKey) (der []byte, err error) {
	return nil, errors.New("Built without ISARA Toolkit")
}
