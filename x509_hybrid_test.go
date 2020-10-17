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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"testing"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func createHybridCertificateRequest(t *testing.T) (csr *x509.CertificateRequest, priv crypto.Signer, qspriv *DilithiumPrivateKey) {
	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"CA"},
		Province:           []string{"ON"},
		Locality:           []string{"Waterloo"},
		Organization:       []string{"ISARA"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	privClassic, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}
	csrBytesClassic, err := x509.CreateCertificateRequest(rand.Reader, &template, privClassic)
	if err != nil {
		t.Fatalf("Error CreateCertificateRequest\nError: %s", err)
	}

	variant := IqrDILITHIUM128
	privQS, err := GenerateDilithiumPrivateKey(variant, rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Dilithium Private Key\nError: %s", err)
	}

	csrBytes, err := ExtendCertificateReqAlt(csrBytesClassic, privClassic, privQS)
	if err != nil {
		t.Fatalf("Error ExtendCertificateReqAlt\nError: %s", err)
	}

	csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("Error ParseCertificateRequest\nError: %s", err)
	}
	return csr, privClassic, privQS
}

func TestCreateHybridCSR(t *testing.T) {
	var ctx *IqrContext
	err := IqrCreateContext(&ctx)
	if err != nil {
		t.Fatalf("IqrCreateContext error: %s\n", err)
	}
	defer IqrDestroyContext(&ctx)

	csr, _, _ := createHybridCertificateRequest(t)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr.Raw,
	})

	fmt.Printf("\nHybrid QS CSR:\n\n")
	fmt.Println(string(csrPEM))

	// Verify the CSR
	err = csr.CheckSignature()
	if err != nil {
		log.Fatal("CSR CheckSignature failed", err)
	}

	err = CheckAltReqSignature(csr)
	if err != nil {
		log.Fatal("QS CSR CheckAltReqSignature failed", err)
	}
}
