#!/bin/bash

# Exit on error
set -e

# Show commands
set -x

if [ -z "${IQR_TOOLKIT_PATH}" ]; then
echo "IQR_TOOLKIT_PATH not defined."
  exit 1
fi

# Set the IQR toolkit path.
#export IQR_TOOLKIT_PATH=
export CGO_ENABLED=1
export CGO_CPPFLAGS=-I$IQR_TOOLKIT_PATH
export CGO_LDFLAGS=$IQR_TOOLKIT_PATH/lib_x86_64/libiqr_toolkit.a

# Generate Dilithium private key
$OPENSSL genpkey -engine $ENGINE -algorithm dilithium -pkeyopt parameter_set:Dilithium_III_SHAKE_r2 -out isara_dilithium_priv.pem

# Run the test case.
go run .

# Check if we can extract the public key.
$OPENSSL pkey -engine $ENGINE -in dilithium_128_pri.pem -pubout -noout -text | grep DILITHIUM_III_SHAKE_r2 || \
        { echo "** Incorrect parameter set, DILITHIUM_III_SHAKE_r2 expected"; exit 1; }

$OPENSSL pkey -engine $ENGINE -in dilithium_160_pri.pem -pubout -noout -text | grep DILITHIUM_IV_SHAKE_r2 || \
        { echo "** Incorrect parameter set, DILITHIUM_IV_SHAKE_r2 expected"; exit 1; }

echo Passed
rm *.pem