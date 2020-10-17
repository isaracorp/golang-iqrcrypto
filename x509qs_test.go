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

// +build cgo

package iqrcrypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
)

func TestDilithiumCSR(t *testing.T) {
	var ctx *IqrContext
	err := IqrCreateContext(&ctx)
	if err != nil {
		t.Fatalf("IqrCreateContext error: %s\n", err)
	}
	defer IqrDestroyContext(&ctx)

	variant := IqrDILITHIUM128
	privQS, err := GenerateDilithiumPrivateKey(variant, rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Dilithium Private Key\nError: %s", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.isara.com",
			Organization: []string{"Eng."},
		},
		DNSNames:       []string{"test.isara.com"},
		EmailAddresses: []string{"info@isara.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
	}

	qscrs, err := CreateQSCertificateRequest(rand.Reader, &template, privQS)
	if err != nil {
		t.Fatalf("Error CreateQSCertificateRequest: %s", err)
	}

	csr, err := x509.ParseCertificateRequest(qscrs)
	if err != nil {
		t.Fatalf("Error ParseCertificateRequest: %s", err)
	}

	sig, err := asn1.Marshal(asn1.BitString{
		Bytes:     csr.Signature,
		BitLength: len(csr.Signature) * 8,
	})
	if err != nil {
		t.Fatalf("Error serializing signature: %s", err)
	}

	err = checkQSSignature(csr.RawTBSCertificateRequest, sig, privQS.Public())
	if err != nil {
		t.Fatalf("Error checkQSSignature: %s", err)
	}
}
