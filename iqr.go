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
// #include "include/iqr_dilithium.h"
import "C"
import (
	"errors"
	"io"
	"unsafe"
)

// IQR_HASHALGO_SHA2_256 SHA2-256 algorithm type identifier.
var IQR_HASHALGO_SHA2_256 = 2

// IQR_HASHALGO_SHA2_384 SHA2-384 algorithm type identifier.
var IQR_HASHALGO_SHA2_384 = 3

// IQR_HASHALGO_SHA2_512 SHA2-512 algorithm type identifier.
var IQR_HASHALGO_SHA2_512 = 4

// IQR_HASHALGO_SHA3_256 SHA3-256 algorithm type identifier.
var IQR_HASHALGO_SHA3_256 = 5

// IQR_HASHALGO_SHA3_512 SHA3-512 algorithm type identifier.
var IQR_HASHALGO_SHA3_512 = 6

// IQR_HASH_DEFAULT_SHA2_256 Internal SHA2-256 implementation.
var IQR_HASH_DEFAULT_SHA2_256 C.iqr_HashCallbacks = C.IQR_HASH_DEFAULT_SHA2_256

// IQR_HASH_DEFAULT_SHA2_384 Internal SHA2-384 implementation.
var IQR_HASH_DEFAULT_SHA2_384 C.iqr_HashCallbacks = C.IQR_HASH_DEFAULT_SHA2_384

// IQR_HASH_DEFAULT_SHA2_512 Internal SHA2-512 implementation.
var IQR_HASH_DEFAULT_SHA2_512 C.iqr_HashCallbacks = C.IQR_HASH_DEFAULT_SHA2_512

// IQR_HASH_DEFAULT_SHA3_256 Internal SHA3-256 implementation.
var IQR_HASH_DEFAULT_SHA3_256 C.iqr_HashCallbacks = C.IQR_HASH_DEFAULT_SHA3_256

// IQR_HASH_DEFAULT_SHA3_512 Internal SHA3-512 implementation.
var IQR_HASH_DEFAULT_SHA3_512 C.iqr_HashCallbacks = C.IQR_HASH_DEFAULT_SHA3_512

// IqrContext The Context object
type IqrContext = C.iqr_Context

// IqrRNG Random Number Generator object.
type IqrRNG = C.iqr_RNG

// IqrRetval return value of Iqr function.
type IqrRetval = C.iqr_retval

type sizeT = C.size_t

// IQR_OK function completed successfully.
const IQR_OK = C.IQR_OK

// QSPrivateKey is an interface for an opaque QS private key that can be used for
// signing operations.
type QSPrivateKey interface {
	QSKeyType() string
	Destroy() error
}

// IqrStrError converts Iqr return value to readable string.
func IqrStrError(ret IqrRetval) string {
	return C.GoString(C.iqr_StrError(ret))
}

// IqrError converts Iqr return value to Go error object.
func IqrError(ret IqrRetval) error {
	if ret == IQR_OK {
		return nil
	}
	return errors.New(C.GoString(C.iqr_StrError(ret)))
}

// IqrCreateContext creates and initializes a Context object.
func IqrCreateContext(ctx **IqrContext) error {
	ret := C.iqr_CreateContext(ctx)
	return IqrError(ret)
}

// IqrDestroyContext destroys a context object.
func IqrDestroyContext(ctx **IqrContext) error {
	ret := C.iqr_DestroyContext(ctx)
	return IqrError(ret)
}

// IqrHashRegisterCallbacks registers a hashing implementation.
func IqrHashRegisterCallbacks(ctx *IqrContext, hashAlgoType int, cb C.iqr_HashCallbacks) error {
	ret := C.iqr_HashRegisterCallbacks(ctx, C.iqr_HashAlgorithmType(hashAlgoType), &cb)
	return IqrError(ret)
}

// IqrRNGCreateHMACDRBG creates an HMAC-DRBG Random Number Generator.
func IqrRNGCreateHMACDRBG(ctx *IqrContext, hashAlgoType int, rng **IqrRNG) error {
	ret := C.iqr_RNGCreateHMACDRBG(ctx, C.iqr_HashAlgorithmType(hashAlgoType), rng)
	return IqrError(ret)
}

// IqrRNGInitialize creates and initializes a Random Number Generator.
func IqrRNGInitialize(rng **IqrRNG, seed []byte) error {
	ret := C.iqr_RNGInitialize(*rng, (*C.uint8_t)(unsafe.Pointer(&seed[0])), sizeT(len(seed)))
	return IqrError(ret)
}

// IqrRNGDestroy destroys a Random Number Generator.
func IqrRNGDestroy(rng **IqrRNG) error {
	ret := C.iqr_RNGDestroy(rng)
	return IqrError(ret)
}

// IqrInitRNG Convenient function to create a RNG. The returned RNG must be
// destroyed using the IqrRNGDestroy function.
func IqrInitRNG(ctx **IqrContext, rng **IqrRNG, rand io.Reader) error {
	// This sets the hashing functions that will be used globally.
	err := IqrHashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, IQR_HASH_DEFAULT_SHA3_512)
	if err != nil {
		return err
	}

	// This lets us give satisfactory randomness to the algorithm.
	err = IqrRNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA3_512, rng)
	if err != nil {
		return err
	}

	const seedLen int = 64 // For IQR_HASHALGO_SHA3_512, 512/8
	seed := make([]byte, seedLen)
	length, err := rand.Read(seed)
	if err != nil {
		return err
	}
	if length != seedLen {
		return errors.New("Seed length too short")
	}
	return IqrRNGInitialize(rng, seed)
}
