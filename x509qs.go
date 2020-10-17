// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
//
// On UNIX systems the environment variables SSL_CERT_FILE and SSL_CERT_DIR
// can be used to override the system default locations for the SSL certificate
// file and SSL certificate files directory, respectively.

// +build cgo

// Package iqrcrypto privides Quantum-Safe algorithms and certificates using
// ISARA's Quantum Resistant Toolkit.
package iqrcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"
)

// Quantum-Safe related variables.

type attributeValue struct {
	Type  interface{}
	Value interface{} `asn1:"omitempty"`
}

type attributeValueSET struct {
	Type  asn1.ObjectIdentifier
	Value []attributeValue `asn1:"set"`
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// SignatureAlgorithmQS Quantum-Safe algorithms.
type SignatureAlgorithmQS int

// List of supported Quantum-Safe algorithms
const (
	UnknownSignatureAlgorithm SignatureAlgorithmQS = iota
	DILITHIUM
	HSS
)

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519
	default:
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: only RSA and ECDSA public keys supported")
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func marshalDilithiumPublicKey(pub *IqrDilithiumPublicKey, params *IqrDilithiumParams, variant *IqrDilithiumVariant) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	var qsPubSize int64
	err = IqrDilithiumGetPublicKeySize(params, &qsPubSize)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}
	qsPubBuf := make([]byte, qsPubSize)
	IqrDilithiumExportPublicKey(pub, qsPubBuf, qsPubSize)
	publicKeyBytes, err = asn1.Marshal(qsPubBuf)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, errors.New("failed to serialise qs pub buf: " + err.Error())
	}

	publicKeyAlgorithm.Algorithm = OidDilithiumSignatureScheme
	if variant == IqrDILITHIUM128 {
		publicKeyAlgorithm.Parameters = OidDilithium_III_SHAKE_r2
	} else if variant == IqrDILITHIUM160 {
		publicKeyAlgorithm.Parameters = OidDilithium_IV_SHAKE_r2
	} else {
		return nil, pkix.AlgorithmIdentifier{}, errors.New("invalid Dilithium variant")
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type publicKeyTypeQS struct {
	SigScheme asn1.ObjectIdentifier
	KeyParam  asn1.RawValue `asn1:"optional"`
}

type publicKeyInfoQS struct {
	PubkeyType publicKeyTypeQS
	PubKey     asn1.BitString
}

func isRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

// OIDs for signature algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
// md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
// md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
// sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
// dsaWithSha1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
// ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
// 	  iso(1) member-body(2) us(840) ansi-x962(10045)
//    signatures(4) ecdsa-with-SHA1(1)}
//
//
// RFC 4055 5 PKCS #1 Version 1.5
//
// sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
// sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
//
// RFC 5758 3.1 DSA Signature Algorithms
//
// dsaWithSha256 OBJECT IDENTIFIER ::= {
//    joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//    csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
// id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// rsaPSSParameters returns an asn1.RawValue suitable for use as the Parameters
// in an AlgorithmIdentifier that specifies RSA PSS.
func rsaPSSParameters(hashFunc crypto.Hash) asn1.RawValue {
	var hashOID asn1.ObjectIdentifier

	switch hashFunc {
	case crypto.SHA256:
		hashOID = oidSHA256
	case crypto.SHA384:
		hashOID = oidSHA384
	case crypto.SHA512:
		hashOID = oidSHA512
	}

	params := pssParameters{
		Hash: pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		},
		MGF: pkix.AlgorithmIdentifier{
			Algorithm: oidMGF1,
		},
		SaltLength:   hashFunc.Size(),
		TrailerField: 1,
	}

	mgf1Params := pkix.AlgorithmIdentifier{
		Algorithm:  hashOID,
		Parameters: asn1.NullRawValue,
	}

	var err error
	params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
	if err != nil {
		panic(err)
	}

	serialized, err := asn1.Marshal(params)
	if err != nil {
		panic(err)
	}

	return asn1.RawValue{FullBytes: serialized}
}

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = oidSignatureEd25519
)

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func subjectBytes(cert *x509.Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPublicKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo x509.SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType x509.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		hashFunc = crypto.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	case ed25519.PublicKey:
		pubType = x509.Ed25519
		sigAlgo.Algorithm = oidSignatureEd25519

	case *IqrDilithiumPublicKey:
		sigAlgo.Algorithm = OidDilithiumSignatureScheme

	default:
		err = errors.New("x509: only RSA, ECDSA, Ed25519 and Dilithium keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 && pubType != x509.Ed25519 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			if isRSAPSS(requestedSigAlgo) {
				sigAlgo.Parameters = rsaPSSParameters(hashFunc)
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// oidNotInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}

// oidExtensionRequest is a PKCS#9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// CreateQSCertificateRequest creates a new certificate request based on a
// template. It is similar to x509.CreateCertificateRequest except it also
// support Dilithium key. It does not create classic and quantum-safe hybird
// certificate request. To do that, use the CreateHybridCertificateRequest
// function.
//
// The returned slice is the certificate request in ASN.1 encoding.
func CreateQSCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv interface{}) (csr []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	var hashFunc crypto.Hash
	var sigAlgo pkix.AlgorithmIdentifier
	hashFunc, sigAlgo, err = signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	dilithiumKey, ok := priv.(*DilithiumPrivateKey)
	if !ok {
		return nil, errors.New("Error converting to Dilithium key")
	}
	qspubkey := dilithiumKey.PubKey
	params := dilithiumKey.Params
	variant := dilithiumKey.Variant
	publicKeyBytes, publicKeyAlgorithm, err = marshalDilithiumPublicKey(qspubkey, params, variant)
	if err != nil {
		return nil, err
	}

	var extensions []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	extensions = append(extensions, template.ExtraExtensions...)

	// Make a copy of template.Attributes because we may alter it below.
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}

	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}

			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)

			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}

				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}

			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	signed := tbsCSRContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	var signature []byte
	signature, err = key.Sign(rand, signed, hashFunc)
	if err != nil {
		return
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func convertAttributeValueToRaw(q attributeValueSET) (raw *asn1.RawValue, err error) {
	b, err := asn1.Marshal(q)
	if err != nil {
		return nil, errors.New("x509qs: failed to serialise qs attribute: " + err.Error())
	}

	var rawValue asn1.RawValue
	if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
		return nil, err
	}
	return &rawValue, nil
}

func getQSPublicKey(keyInfoQS *publicKeyInfoQS, signature []byte) (pubKey interface{}, err error) {
	var ctx *IqrContext

	err = IqrCreateContext(&ctx)
	if err != nil {
		return nil, err
	}
	defer IqrDestroyContext(&ctx)

	var variant *IqrDilithiumVariant = nil
	if keyInfoQS.PubkeyType.SigScheme.Equal(OidDilithiumSignatureScheme) {

		if bytes.Equal(keyInfoQS.PubkeyType.KeyParam.FullBytes, OidDilithium_III_SHAKE_r2.FullBytes) {
			variant = IqrDILITHIUM128
		} else if bytes.Equal(keyInfoQS.PubkeyType.KeyParam.FullBytes, OidDilithium_IV_SHAKE_r2.FullBytes) {
			variant = IqrDILITHIUM160
		} else {
			return nil, errors.New("getQSPublicKey: Unknown QS key type, supported types: IqrDILITHIUM128, IqrDILITHIUM160")
		}

		var params *IqrDilithiumParams
		err = IqrDilithiumCreateParams(ctx, variant, &params)
		if err != nil {
			return nil, err
		}
		defer IqrDilithiumDestroyParams(&params)

		// Need to create params from the variant of the key.
		// then verify the key.
		var qsSigSize int64
		err = IqrDilithiumGetSignatureSize(params, &qsSigSize)
		if err != nil {
			return nil, err
		}

		var pubKey *IqrDilithiumPublicKey
		// Remove Bitstring tag and length from the bytes before passing to the function.
		var keyData []byte
		_, err = asn1.Unmarshal(keyInfoQS.PubKey.Bytes, &keyData)
		err = IqrDilithiumImportPublicKey(params, keyData, int64(len(keyData)), &pubKey)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	} else if keyInfoQS.PubkeyType.SigScheme.Equal(OidHSSSignatureScheme) {
		var params *IqrHSSParams = nil
		var signatureData asn1.BitString
		_, err = asn1.Unmarshal(signature, &signatureData)
		if err != nil {
			return nil, err
		}

		err = IqrHashRegisterCallbacks(ctx, IQR_HASHALGO_SHA2_256, IQR_HASH_DEFAULT_SHA2_256)
		if err != nil {
			return nil, err
		}

		err = IqrHSSCreateParamsFromSignature(ctx, signatureData.Bytes, int64(len(signatureData.Bytes)), &params)
		if err != nil {
			return nil, err
		}
		defer IqrHSSDestroyParams(&params)

		// Import public key
		var publicKey *IqrHSSPublicKey = nil
		var keyData []byte
		_, err = asn1.Unmarshal(keyInfoQS.PubKey.Bytes, &keyData)
		if err != nil {
			return nil, err
		}
		err = IqrHSSImportPublicKey(params, keyData, int64(len(keyData)), &publicKey)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}

	return nil, errors.New("Unknown key type")
}

// checkQSSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkQSSignature(signed, signature []byte, publicKey crypto.PublicKey) (err error) {

	var signatureData asn1.BitString
	_, err = asn1.Unmarshal(signature, &signatureData)
	if err != nil {
		return err
	}

	switch pub := publicKey.(type) {
	case *IqrDilithiumPublicKey:
		err = IqrDilithiumVerify(pub, signed, int64(len(signed)), signatureData.Bytes, int64(len(signatureData.Bytes)))
		return err
	case *IqrHSSPublicKey:
		err = IqrHSSVerify(pub, signed, int64(len(signed)), signatureData.Bytes, int64(len(signatureData.Bytes)))
		return err
	}
	return x509.ErrUnsupportedAlgorithm
}

// CheckQSSignatureFrom verifies that the Quantum-Safe (Dilithium or HSS) signature of the given certificate is valid
// from parent.
func CheckQSSignatureFrom(c *x509.Certificate, parent *x509.Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}

	var ctx *IqrContext
	err := IqrCreateContext(&ctx)
	if err != nil {
		return err
	}
	defer IqrDestroyContext(&ctx)

	// Parse the parent TBS so that we can get its public key later.
	var tbsCertParent tbsCertificate
	rest, err := asn1.Unmarshal(parent.RawTBSCertificate, &tbsCertParent)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return asn1.SyntaxError{Msg: "trailing data"}
	}

	if tbsCertParent.PublicKey.Algorithm.Algorithm.Equal(OidDilithiumSignatureScheme) {
		var dilithiumPubKey *IqrDilithiumPublicKey = nil
		var variant *IqrDilithiumVariant = nil
		var params *IqrDilithiumParams = nil
		var pubKeyBytes = tbsCertParent.PublicKey.Raw
		err = IqrDilithiumImportPublicKeyFromASN1(ctx, pubKeyBytes, int64(len(pubKeyBytes)), &dilithiumPubKey, &variant, &params)
		if err != nil {
			return err
		}
		defer IqrDilithiumDestroyPublicKey(&dilithiumPubKey)
		return IqrDilithiumVerify(dilithiumPubKey, c.RawTBSCertificate, int64(len(c.RawTBSCertificate)), c.Signature, int64(len(c.Signature)))
	} else if tbsCertParent.PublicKey.Algorithm.Algorithm.Equal(OidHSSSignatureScheme) {
		err = IqrHashRegisterCallbacks(ctx, IQR_HASHALGO_SHA2_256, IQR_HASH_DEFAULT_SHA2_256)
		if err != nil {
			return err
		}

		var params *IqrHSSParams = nil
		err = IqrHSSCreateParamsFromSignature(ctx, c.Signature, int64(len(c.Signature)), &params)
		if err != nil {
			return err
		}

		var hssPubKey *IqrHSSPublicKey = nil
		var pubKeyBytes = tbsCertParent.PublicKey.Raw
		err = IqrHSSImportPublicKeyFromASN1(ctx, pubKeyBytes, int64(len(pubKeyBytes)), &hssPubKey, params)
		if err != nil {
			return err
		}
		defer IqrHSSDestroyPublicKey(&hssPubKey)
		return IqrHSSVerify(hssPubKey, c.RawTBSCertificate, int64(len(c.RawTBSCertificate)), c.Signature, int64(len(c.Signature)))
	}
	return x509.ErrUnsupportedAlgorithm
}
