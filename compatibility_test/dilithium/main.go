package main

import (
	"crypto/rand"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/isaracorp/golang-iqrcrypto"
)

func genDilithiumKey(variant *iqrcrypto.IqrDilithiumVariant, filename string) {
	privKey, err := iqrcrypto.GenerateDilithiumPrivateKey(variant, rand.Reader)
	if err != nil {
		log.Fatalf("GenerateDilithiumPrivateKey failed: %s\n", err)
	}
	derKey, err := iqrcrypto.IqrDilithiumExportPrivateKeyPKCS8(privKey)
	if err != nil {
		log.Fatalf("IqrDilithiumExportPrivateKeyPKCS8 failed: %s\n", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: derKey,
	})
	ioutil.WriteFile(filename, pemKey, 0644)
}

func main() {
	genDilithiumKey(iqrcrypto.IqrDILITHIUM128, "dilithium_128_pri.pem")
	genDilithiumKey(iqrcrypto.IqrDILITHIUM160, "dilithium_160_pri.pem")

	// Test key loading.
	dilithiumPrivKey, err := ioutil.ReadFile("isara_dilithium_priv.pem")
	if err != nil {
		log.Fatalf("Failed to read file: %s\n", err)
	}
	qsPrivDer, _ := pem.Decode([]byte(dilithiumPrivKey))
	if qsPrivDer == nil {
		log.Fatalf("Failed to decode key: %s\n", err)
	}

	var ctx *iqrcrypto.IqrContext
	err = iqrcrypto.IqrCreateContext(&ctx)
	if err != nil {
		log.Fatalf("IqrCreateContext error: %s\n", err)
	}
	defer iqrcrypto.IqrDestroyContext(&ctx)

	var qsPrivKey *iqrcrypto.IqrDilithiumPrivateKey = nil
	var params *iqrcrypto.IqrDilithiumParams = nil
	var variant *iqrcrypto.IqrDilithiumVariant = nil
	err = iqrcrypto.IqrDilithiumImportPrivateKeyFromPKCS8(ctx, qsPrivDer.Bytes, int64(len(qsPrivDer.Bytes)), &qsPrivKey, &variant, &params)
	if err != nil {
		log.Fatal("error import QS priv key", err)
	}
	if variant != iqrcrypto.IqrDILITHIUM128 {
		log.Fatal("Incorrect variant.")
	}
}
