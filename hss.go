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

package iqrcrypto

// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include "include/iqr_context.h"
// #include "include/iqr_rng.h"
// #include "include/iqr_hss.h"
import "C"

import (
	"encoding/asn1"
	"errors"
	"unsafe"
)

var (
	// OidHSSSignatureScheme Hierarchical-Signature-Scheme
	OidHSSSignatureScheme = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 17}
)

// IqrHSSParams the HSS algorithm's domain parameters.
type IqrHSSParams = C.iqr_HSSParams

// IqrHSSPublicKey handle to HSS public key.
type IqrHSSPublicKey = C.iqr_HSSPublicKey

// IqrHSSCreateParamsFromSignature Create an HSS Parameters object using a signature.
func IqrHSSCreateParamsFromSignature(ctx *IqrContext, sig []byte, sigSize int64, params **IqrHSSParams) error {
	ret := C.iqr_HSSCreateParamsFromSignature(ctx, (*C.uint8_t)(unsafe.Pointer(&sig[0])), sizeT(sigSize), params)
	return IqrError(ret)
}

// IqrHSSGetPublicKeySize gets HSS public key size.
func IqrHSSGetPublicKeySize(params *IqrHSSParams, publicKeySize *int64) error {

	var pubKeySize sizeT
	ret := C.iqr_HSSGetPublicKeySize(params, &pubKeySize)
	*publicKeySize = int64(pubKeySize)
	return IqrError(ret)
}

// IqrHSSExportPublicKey exports HSS public key.
func IqrHSSExportPublicKey(pubKey *IqrHSSPublicKey, buf []byte, size int64) error {
	ret := C.iqr_HSSExportPublicKey(pubKey, (*C.uint8_t)(unsafe.Pointer(&buf[0])), sizeT(size))
	return IqrError(ret)
}

// IqrHSSImportPublicKey imports HSS public key.
func IqrHSSImportPublicKey(params *IqrHSSParams, buf []byte, size int64, publicKey **IqrHSSPublicKey) error {
	ret := C.iqr_HSSImportPublicKey(params, (*C.uint8_t)(unsafe.Pointer(&buf[0])), sizeT(size), publicKey)
	return IqrError(ret)
}

// IqrHSSImportPublicKeyFromASN1 imports public key from asn.1 encode public key.
func IqrHSSImportPublicKeyFromASN1(ctx *IqrContext, der []byte, size int64, publicKey **IqrHSSPublicKey,
	params *IqrHSSParams) error {

	if len(der) != int(size) {
		return errors.New("Size not matched")
	}

	pubkey := pkixPublicKey{}
	_, err := asn1.Unmarshal(der, &pubkey)
	if err != nil {
		return errors.New("Cannot unmarshall private key")
	}

	algo := pubkey.Algo.Algorithm
	//Check algo is HSS
	if !equalOID(algo, OidHSSSignatureScheme) {
		return errors.New("Incorrect signature OID")
	}

	var publicKeySize int64
	IqrHSSGetPublicKeySize(params, &publicKeySize)
	*publicKey = nil
	buf := pubkey.BitString.Bytes
	bufLen := len(buf)
	if int(publicKeySize) > bufLen {
		return errors.New("Incorrect public key size")
	}

	// The first four bytes are Bitstring tag and length.
	content := []byte{}
	_, err = asn1.Unmarshal(buf, &content)
	if err != nil {
		return errors.New("Cannot unmarshall key data")
	}
	err = IqrHSSImportPublicKey(params, content, publicKeySize, publicKey)
	return err
}

// IqrHSSVerify verifies HSS signature.
// sigSize must be exact the same value returned by IqrHSSGetSingatureSize
func IqrHSSVerify(pubKey *IqrHSSPublicKey, message []byte, messageSize int64, sig []byte, sigSize int64) error {
	ret := C.iqr_HSSVerify(pubKey, (*C.uint8_t)(unsafe.Pointer(&message[0])), sizeT(messageSize),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), sizeT(sigSize))
	return IqrError(ret)
}

// IqrHSSDestroyPublicKey destroys the HSS public key and releases it from memory.
func IqrHSSDestroyPublicKey(publicKey **IqrHSSPublicKey) error {
	ret := C.iqr_HSSDestroyPublicKey(publicKey)
	return IqrError(ret)
}

// IqrHSSDestroyParams destroys HSS parameters and release it from memory.
func IqrHSSDestroyParams(params **IqrHSSParams) error {
	ret := C.iqr_HSSDestroyParams(params)
	return IqrError(ret)
}
