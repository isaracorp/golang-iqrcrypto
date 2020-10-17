package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"net/url"

	"github.com/isaracorp/golang-iqrcrypto"
)

func opensslHybridCSRTest(ctx *iqrcrypto.IqrContext) {
	hybridCSRPEM, err := ioutil.ReadFile("server_hybrid.csr")
	hybridCSRDER, _ := pem.Decode([]byte(hybridCSRPEM))
	if hybridCSRDER == nil {
		log.Fatalf("Failed to load hybrid CSR\n")
	}

	csrHybrid, err := x509.ParseCertificateRequest(hybridCSRDER.Bytes)
	if err != nil {
		log.Fatal("ParseCertificateRequest, failed", err)
	}

	err = csrHybrid.CheckSignature()
	if err != nil {
		log.Fatal("QS CSR CheckSignature failed", err)
	}

	// Check that the hybrid certificate request has valid QS signature.
	err = iqrcrypto.CheckAltReqSignature(csrHybrid)
	if err != nil {
		log.Fatal("QS CSR CheckAltReqSignature failed", err)
	}
}

func hssCertTest(ctx *iqrcrypto.IqrContext) {
	hybridRootCertPEM, err := ioutil.ReadFile("root_hybrid_hss_cert.pem")
	hybridRootCertDER, _ := pem.Decode([]byte(hybridRootCertPEM))
	if hybridRootCertDER == nil {
		log.Fatalf("Failed to load root hybrid certificate\n")
	}

	rootCert, err := x509.ParseCertificate(hybridRootCertDER.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root hybrid certificate: %s\n", err)
	}

	hybridCertPEM, err := ioutil.ReadFile("server_hybrid_hss.crt")
	if err != nil {
		log.Fatalf("Cannot read file: %s", err)
	}
	hybridCertDER, _ := pem.Decode([]byte(hybridCertPEM))
	if hybridCertDER == nil {
		log.Fatalf("Failed to load hybrid certificate\n")
	}

	hybridCert, err := x509.ParseCertificate(hybridCertDER.Bytes)
	if err != nil {
		log.Fatalf("Error ParseCertificate\nError: %s", err)
	}
	err = hybridCert.CheckSignatureFrom(rootCert)
	if err != nil {
		log.Fatalf("Error CheckSignatureFrom\nError: %s", err)
	}

	err = iqrcrypto.CheckAltSignatureFrom(hybridCert, rootCert)
	if err != nil {
		log.Fatalf("Error CheckAltSignatureFrom\nError: %s", err)
	}
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func golangHybridCSRTest(ctx *iqrcrypto.IqrContext) {
	var classicPrivKey crypto.Signer
	classicPrivKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		log.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	variant := iqrcrypto.IqrDILITHIUM128
	privQS, err := iqrcrypto.GenerateDilithiumPrivateKey(variant, rand.Reader)
	if err != nil {
		log.Fatalf("Error generating Dilithium Private Key\nError: %s", err)
	}
	defer privQS.Destroy()

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "fake_domain.com",
			Country:            []string{"CA"},
			Province:           []string{"ON"},
			Locality:           []string{"Waterloo"},
			Organization:       []string{"ISARA"},
			OrganizationalUnit: []string{"QA"},
		},
		EmailAddresses: []string{"test@isara.com"},
		DNSNames:       []string{"test.example.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, classicPrivKey)
	if err != nil {
		log.Fatalf("Error CreateCertificateRequest: Error: %s\n", err)
	}

	classicCsrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})
	ioutil.WriteFile("golang_classic_san_csr.pem", classicCsrPEM, 0644)

	// Extend CSR with QS signature
	csrqs, err := iqrcrypto.ExtendCertificateReqAlt(csrBytes, classicPrivKey, privQS)
	if err != nil {
		log.Fatalf("Error ExtendCertificateReqAlt: Error: %s\n", err)
	}

	certSignReq, err := x509.ParseCertificateRequest(csrqs)
	if err != nil {
		log.Fatalf("Error ParseCertificateRequest: Error: %s\n", err)
	}
	err = iqrcrypto.CheckAltReqSignature(certSignReq)
	if err != nil {
		log.Fatalf("Error CheckAltReqSignature: Error: %s\n", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrqs,
	})

	ioutil.WriteFile("golang_hybrid_csr.pem", csrPEM, 0644)
}

func main() {
	var ctx *iqrcrypto.IqrContext
	err := iqrcrypto.IqrCreateContext(&ctx)
	if err != nil {
		log.Fatalf("IqrCreateContext error: %s\n", err)
	}
	defer iqrcrypto.IqrDestroyContext(&ctx)

	opensslHybridCSRTest(ctx)
	hssCertTest(ctx)
	golangHybridCSRTest(ctx)
}
