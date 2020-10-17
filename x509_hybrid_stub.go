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
	"crypto/x509"
	"errors"
	"io"
)

// ExtendCertificateReqAlt Stub
func ExtendCertificateReqAlt(csrDER []byte, classicPriv interface{}, qsPriv QSPrivateKey) (csrqs []byte, err error) {
	return nil, errors.New("Built without ISARA Toolkit")
}

// CreateHybridCertificateRequest creates a new hybrid certificate request based on a
// classic one.
func CreateHybridCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv interface{},
	qspriv QSPrivateKey) (csr []byte, err error) {
	return nil, errors.New("Built without ISARA Toolkit")
}

// CheckAltReqSignature check that hybrid CSR has a valid alternative signature.
// Currently only support Dilithium key
func CheckAltReqSignature(c *x509.CertificateRequest) error {
	return errors.New("Built without ISARA Toolkit")
}

// CheckAltSignature verifies that the alternative signature is a valid
// signature over signed from c's alternative public key. It is assumed
// that the certificate has been verified by x509.Certificate.CheckSignature.
func CheckAltSignature(c *x509.Certificate, signed, signature []byte) error {
	return errors.New("Built without ISARA Toolkit")
}

// CheckAltSignatureFrom verifies that the alternative signature of the given
// certificate is valid from parent. It is assumed that the certificate has
// been verified by the conventional signature.
func CheckAltSignatureFrom(c *x509.Certificate, parent *x509.Certificate) error {
	return errors.New("Built without ISARA Toolkit")
}
