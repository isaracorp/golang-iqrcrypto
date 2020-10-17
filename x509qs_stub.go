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
	"crypto/x509"
	"errors"
	"io"
)

type SignatureAlgorithmQS int

const (
	UnknownSignatureAlgorithm SignatureAlgorithmQS = iota
	DILITHIUM
	HSS
)

// CreateQSCertificateRequest
func CreateQSCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv interface{}) (csr []byte, err error) {
	return nil, errors.New("Built without ISARA Toolkit")
}

// checkQSSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkQSSignature(signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	return errors.New("Built without ISARA Toolkit")
}
