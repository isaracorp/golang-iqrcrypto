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
	"errors"
)

// SHA2-256 algorithm type identifier.
var IQR_HASHALGO_SHA2_256 = 2

// SHA2-384 algorithm type identifier.
var IQR_HASHALGO_SHA2_384 = 3

// SHA2-512 algorithm type identifier.
var IQR_HASHALGO_SHA2_512 = 4

// SHA3-256 algorithm type identifier.
var IQR_HASHALGO_SHA3_256 = 5

// SHA3-512 algorithm type identifier.
var IQR_HASHALGO_SHA3_512 = 6

const (
	IQR_HASH_DEFAULT_SHA2_256 = iota
	IQR_HASH_DEFAULT_SHA2_384
	IQR_HASH_DEFAULT_SHA2_512
	IQR_HASH_DEFAULT_SHA3_256
	IQR_HASH_DEFAULT_SHA3_512
)

type IqrHSSParams interface{}
type IqrHSSPublicKey interface{}

func IqrHashRegisterCallbacks(ctx *IqrContext, hashAlgoType int, cb interface{}) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSCreateParamsFromSignature
func IqrHSSCreateParamsFromSignature(ctx *IqrContext, sig []byte, sigSize int64, params **IqrHSSParams) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSGetPublicKeySize
func IqrHSSGetPublicKeySize(params *IqrHSSParams, publicKeySize *int64) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSImportPublicKey
func IqrHSSExportPublicKey(pubKey *IqrHSSPublicKey, buf []byte, size int64) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSImportPublicKey
func IqrHSSImportPublicKey(params *IqrHSSParams, buf []byte, size int64, publicKey **IqrHSSPublicKey) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSImportPublicKeyFromASN1
func IqrHSSImportPublicKeyFromASN1(ctx *IqrContext, der []byte, size int64, publicKey **IqrHSSPublicKey,
	params *IqrHSSParams) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSVerify sigSize must be exact the same value returned by IqrHSSGetSingatureSize
func IqrHSSVerify(pubKey *IqrHSSPublicKey, message []byte, messageSize int64, sig []byte, sigSize int64) error {
	return errors.New("Built without ISARA Toolkit")
}

// IqrHSSDestroyPublicKey
func IqrHSSDestroyPublicKey(publicKey **IqrHSSPublicKey) error {
	return errors.New("Built without ISARA Toolkit")
}

func IqrHSSDestroyParams(params **IqrHSSParams) error {
	return errors.New("Built without ISARA Toolkit")
}
