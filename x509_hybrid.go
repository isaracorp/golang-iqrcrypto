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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"strings"
)

// Quantum-Safe related variables.

type altSigValue struct {
	Type  asn1.ObjectIdentifier
	Value []asn1.BitString `asn1:"set"`
}

var (
	oidSubjectAlternativePublicKey = asn1.ObjectIdentifier{2, 5, 29, 72}
	oidAltSignatureAlgorithm       = asn1.ObjectIdentifier{2, 5, 29, 73}
	oidAlternativeSignatureValue   = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// CreateHybridCertificateRequest creates a new hybrid certificate request based on a
// classic one.
//
// The returned slice is a hybrid certificate request in ASN.1 encoding.
func CreateHybridCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv interface{},
	qspriv QSPrivateKey) (csr []byte, err error) {

	if strings.Compare(qspriv.QSKeyType(), "dilithium") != 0 {
		return nil, errors.New("Only Dilithium private key is supported")
	}

	dilithiumKey, ok := qspriv.(*DilithiumPrivateKey)
	if !ok {
		return nil, errors.New("Error converting to Dilithium key")
	}

	qsprivkey := dilithiumKey.PrivKey
	qspubkey := dilithiumKey.PubKey
	variant := dilithiumKey.Variant
	params := dilithiumKey.Params
	if variant != IqrDILITHIUM128 && variant != IqrDILITHIUM160 {
		return nil, errors.New("Unsuported variant")
	}

	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509_hybrid: certificate private key does not implement crypto.Signer")
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	var classicTbs tbsCertificateRequest
	_, err = asn1.Unmarshal(template.RawTBSCertificateRequest, &classicTbs)
	if err != nil {
		return nil, err
	}

	// QS signature scheme
	altSignatureAlgorithmAttr := attributeValueSET{
		Type: oidAltSignatureAlgorithm,
		Value: []attributeValue{
			{
				Type:  OidDilithiumSignatureScheme,
				Value: []byte{},
			},
		},
	}

	// QS parameters
	q, _, err := marshalDilithiumPublicKey(qspubkey, params, variant)
	if err != nil {
		return nil, errors.New("x509_hybrid: failed to serialise qs pub buf: " + err.Error())
	}

	var parameters asn1.RawValue
	if variant == IqrDILITHIUM128 {
		parameters = OidDilithium_III_SHAKE_r2
	} else if variant == IqrDILITHIUM160 {
		parameters = OidDilithium_IV_SHAKE_r2
	}

	subjectAlternativePublicKeyAttr := attributeValueSET{
		Type: oidSubjectAlternativePublicKey,
		Value: []attributeValue{
			{
				Type: pkix.AlgorithmIdentifier{
					Algorithm:  OidDilithiumSignatureScheme,
					Parameters: parameters,
				},
				Value: asn1.BitString{
					Bytes:     q,
					BitLength: len(q) * 8,
				},
			},
		},
	}

	var rawAttributes []asn1.RawValue

	// Append the QS attributes
	// The Alternative Signature Algorithm attribute must be the first attribute.
	rawAltSigAlgo, err := convertAttributeValueToRaw(altSignatureAlgorithmAttr)
	if err != nil {
		return nil, errors.New("x509_hybrid: failed to serialise altSignatureAlgorithmAttr: " + err.Error())
	}
	rawAttributes = append(rawAttributes, *rawAltSigAlgo)

	// Append the other existing ones.
	rawAttributes = append(rawAttributes, classicTbs.RawAttributes...)

	// Append the Alternative Public Key.
	rawAltPubKey, err := convertAttributeValueToRaw(subjectAlternativePublicKeyAttr)
	if err != nil {
		return nil, errors.New("x509_hybrid: failed to serialise subjectAlternativePublicKeyAttr: " + err.Error())
	}
	rawAttributes = append(rawAttributes, *rawAltPubKey)

	// Construct the tbs for QS signing
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
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	// Sign the tbs with QS key.
	var qsSigSize int64
	err = IqrDilithiumGetSignatureSize(params, &qsSigSize)
	if err != nil {
		return nil, err
	}
	var qsSig = make([]byte, int(qsSigSize))
	err = IqrDilithiumSign(qsprivkey, tbsCSRContents, int64(len(tbsCSRContents)), qsSig, qsSigSize)
	if err != nil {
		return nil, err
	}

	altSigVal := altSigValue{
		Type: oidAlternativeSignatureValue,
		Value: []asn1.BitString{
			{
				Bytes:     qsSig,
				BitLength: len(qsSig) * 8,
			},
		},
	}

	b, err := asn1.Marshal(altSigVal)
	if err != nil {
		return nil, errors.New("x509_hybrid: failed to serialise qsSig attribute: " + err.Error())
	}
	var sigRawValue asn1.RawValue
	if _, err := asn1.Unmarshal(b, &sigRawValue); err != nil {
		return nil, err
	}

	// Add Alternative Signature Value to the attributes.
	rawAttributes = append(rawAttributes, sigRawValue)

	// Generate the TBS again after adding the QS signature.
	tbsCSR = tbsCertificateRequest{
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

	tbsCSRContents, err = asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	// Sign again with the classic algorithm.
	var hashFunc crypto.Hash
	var sigAlgo pkix.AlgorithmIdentifier
	hashFunc, sigAlgo, err = signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

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

// ExtendCertificateReqAlt Extend a CSR to add a Quantum-Safe algorithm to the
// Alt extensions.
func ExtendCertificateReqAlt(csrDER []byte, classicPriv interface{}, qsPriv QSPrivateKey) (csrqs []byte, err error) {

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, err
	}

	csrBytes, err := CreateHybridCertificateRequest(rand.Reader, csr, classicPriv, qsPriv)
	if err != nil {
		return nil, err
	}
	return csrBytes, nil
}

// CheckAltReqSignature check that hybrid CSR has a valid alternative signature.
// Currently only support Dilithium key
func CheckAltReqSignature(c *x509.CertificateRequest) error {
	var tbs tbsCertificateRequest
	_, err := asn1.Unmarshal(c.RawTBSCertificateRequest, &tbs)
	if err != nil {
		return err
	}

	// Used to unmarshal public key algorithm.
	type pubKeyValue struct {
		Type  pkix.AlgorithmIdentifier
		Value interface{}
	}

	type attributeValueSET struct {
		Type  asn1.ObjectIdentifier
		Value []pubKeyValue `asn1:"set"`
	}

	var subjectAlternativePublicKeyAttr attributeValueSET
	var rawAttributesNoSig []asn1.RawValue
	var qsSig altSigValue
	var pubKeyType asn1.RawValue
	var pubKeyData asn1.BitString
	for _, attr := range tbs.RawAttributes {
		var tmpSig altSigValue
		_, err := asn1.Unmarshal(attr.FullBytes, &tmpSig)
		if err == nil {
			qsSig = tmpSig
			continue
		} else {
			rawAttributesNoSig = append(rawAttributesNoSig, attr)
		}

		_, err = asn1.Unmarshal(attr.FullBytes, &subjectAlternativePublicKeyAttr)
		if err == nil {
			if subjectAlternativePublicKeyAttr.Type.Equal(oidSubjectAlternativePublicKey) {
				if len(subjectAlternativePublicKeyAttr.Value) > 0 {
					val := subjectAlternativePublicKeyAttr.Value[0]
					pubKeyData = val.Value.(asn1.BitString)
					algo := val.Type
					pubKeyType = algo.Parameters
				} else {
					return errors.New("x509_hybrid: public key not found")
				}
			}
		}
	}

	if len(rawAttributesNoSig) == len(tbs.RawAttributes) {
		return errors.New("x509_hybrid: QS signature not found")
	}

	if pubKeyData.BitLength == 0 {
		return errors.New("x509_hybrid: QS public key not found")
	}

	var ctx *IqrContext

	err = IqrCreateContext(&ctx)
	if err != nil {
		return err
	}
	defer IqrDestroyContext(&ctx)

	// Only Dilithium key is supported.
	var variant *IqrDilithiumVariant = nil
	if bytes.Equal(pubKeyType.FullBytes, OidDilithium_III_SHAKE_r2.FullBytes) {
		variant = IqrDILITHIUM128
	} else if bytes.Equal(pubKeyType.FullBytes, OidDilithium_IV_SHAKE_r2.FullBytes) {
		variant = IqrDILITHIUM160
	} else {
		return errors.New("x509_hybrid: Unknown QS key type, Supported types: IqrDILITHIUM128, IqrDILITHIUM160")
	}

	var params *IqrDilithiumParams
	err = IqrDilithiumCreateParams(ctx, variant, &params)
	if err != nil {
		return err
	}
	defer IqrDilithiumDestroyParams(&params)

	// Need to create params from the variant of the key.
	// then verify the key.
	var qsSigSize int64
	err = IqrDilithiumGetSignatureSize(params, &qsSigSize)
	if err != nil {
		return err
	}

	var pubKey *IqrDilithiumPublicKey
	// Remove Bitstring tag and length from the bytes before passing to the function.
	var keyData []byte
	_, err = asn1.Unmarshal(pubKeyData.Bytes, &keyData)
	if err != nil {
		return err
	}
	err = IqrDilithiumImportPublicKey(params, keyData, int64(len(keyData)), &pubKey)
	if err != nil {
		return err
	}
	defer IqrDilithiumDestroyPublicKey(&pubKey)

	tbsCSR := tbsCertificateRequest{
		Version:       0, // PKCS #10, RFC 2986
		Subject:       tbs.Subject,
		PublicKey:     tbs.PublicKey,
		RawAttributes: rawAttributesNoSig,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return err
	}
	err = IqrDilithiumVerify(pubKey, tbsCSRContents, int64(len(tbsCSRContents)), qsSig.Value[0].Bytes, int64(len(qsSig.Value[0].Bytes)))
	if err != nil {
		return err
	}

	return nil
}

// CheckAltSignature verifies that the alternative signature is a valid
// signature over signed from c's alternative public key. It is assumed
// that the certificate has been verified by x509.Certificate.CheckSignature.
func CheckAltSignature(c *x509.Certificate, signed, signature []byte) error {
	var keyInfoQS publicKeyInfoQS

	for _, e := range c.Extensions {
		if e.Id.Equal(oidSubjectAlternativePublicKey) {
			_, err := asn1.Unmarshal(e.Value, &keyInfoQS)
			if err != nil {
				return err
			}
			pubKey, err := getQSPublicKey(&keyInfoQS, signature)
			if err != nil {
				return err
			}
			switch pubKey.(type) {
			case *IqrHSSPublicKey:
				key := pubKey.(*IqrHSSPublicKey)
				defer IqrHSSDestroyPublicKey(&key)
			case *IqrDilithiumPublicKey:
				key := pubKey.(*IqrDilithiumPublicKey)
				defer IqrDilithiumDestroyPublicKey(&key)
			}
			return checkQSSignature(signed, signature, pubKey)
		}
	}
	return x509.ErrUnsupportedAlgorithm
}

func getAltSignature(c *x509.Certificate) (sig []byte, err error) {

	for _, e := range c.Extensions {
		if e.Id.Equal(oidAlternativeSignatureValue) {
			return e.Value, nil
		}
	}
	return nil, errors.New("Alternative signature not found")
}

// CheckAltSignatureFrom verifies that the alternative signature of the given
// certificate is valid from parent. It is assumed that the certificate has
// been verified by the conventional signature.
func CheckAltSignatureFrom(c *x509.Certificate, parent *x509.Certificate) error {
	signature, err := getAltSignature(c)
	if err != nil {
		return err
	}

	var tbsContent tbsCertificate
	_, err = asn1.Unmarshal(c.RawTBSCertificate, &tbsContent)
	if err != nil {
		return err
	}

	// Generate the QS TBS.
	// It does not contain the classic algorithm identifier.
	// The alternative signature must also be removed.
	tbsContent.Raw = nil
	tbsContent.SignatureAlgorithm = pkix.AlgorithmIdentifier{}

	classicExtensions := []pkix.Extension{}
	for _, e := range tbsContent.Extensions {
		if e.Id.Equal(oidAlternativeSignatureValue) {
			// Skip the alternative signature.
			continue
		}
		classicExtensions = append(classicExtensions, e)
	}
	tbsContent.Extensions = classicExtensions

	rawTBS, err := asn1.Marshal(tbsContent)
	if err != nil {
		return err
	}
	return CheckAltSignature(parent, rawTBS, signature)
}
