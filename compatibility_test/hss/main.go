package main

import (
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/isaracorp/golang-iqrcrypto"
)

func main() {
	var ctx *iqrcrypto.IqrContext
	err := iqrcrypto.IqrCreateContext(&ctx)
	if err != nil {
		log.Fatalf("IqrCreateContext error: %s\n", err)
	}
	defer iqrcrypto.IqrDestroyContext(&ctx)

	// Test key loading.
	hssPubKey, err := ioutil.ReadFile("isara_hss_pub.pem")
	if err != nil {
		log.Fatalf("Failed to read file: %s\n", err)
	}
	qsPubDer, _ := pem.Decode([]byte(hssPubKey))
	if qsPubDer == nil {
		log.Fatalf("Failed to decode key: %s\n", err)
	}

	err = iqrcrypto.IqrHashRegisterCallbacks(ctx, iqrcrypto.IQR_HASHALGO_SHA2_256, iqrcrypto.IQR_HASH_DEFAULT_SHA2_256)
	if err != nil {
		log.Fatalf("IqrHashRegisterCallbacks ret is: %s\n", err)
	}

	sig, err := ioutil.ReadFile("hss_signature.bin")
	if err != nil {
		log.Fatalf("Failed to read HSS signature: %s\n", err)
	}

	var params *iqrcrypto.IqrHSSParams = nil
	err = iqrcrypto.IqrHSSCreateParamsFromSignature(ctx, sig, int64(len(sig)), &params)
	if err != nil {
		log.Fatalf("IqrHSSCreateParamsFromSignature ret is: %s\n", err)
	}

	var publicKey *iqrcrypto.IqrHSSPublicKey = nil
	err = iqrcrypto.IqrHSSImportPublicKeyFromASN1(ctx, qsPubDer.Bytes, int64(len(qsPubDer.Bytes)), &publicKey, params)
	if err != nil {
		log.Fatalf("IqrHSSImportPublicKeyFromASN1 error: %s", err)
	}

	msgFile := "testdata/message.txt"
	msg, err := ioutil.ReadFile(msgFile)
	if err != nil {
		log.Fatalf("Failed to read %s\n", msgFile)
	}
	err = iqrcrypto.IqrHSSVerify(publicKey, msg, int64(len(msg)), sig, int64(len(sig)))
	if err != nil {
		log.Fatalf("IqrHSSVerify failed: %s\n", err)
	}
	log.Println("HSS signature verified")
}
