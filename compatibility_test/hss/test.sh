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
unameOut="$(uname -s)"
case "${unameOut}" in
    MINGW*)
        export CGO_LDFLAGS=$IQR_TOOLKIT_PATH/lib_x86_64/libiqr_toolkit_static.lib
        ;;
    *)
        export CGO_LDFLAGS=$IQR_TOOLKIT_PATH/lib_x86_64/libiqr_toolkit.a
        ;;
esac

# Generate HSS key pair
$OPENSSL genpkey -engine $ENGINE -algorithm hss -pkeyopt state_filename:hss_state.bin -pkeyopt sign_operations:2E20 -pkeyopt optimization:fast -pkeyopt strategy:full -out isara_hss_key.pem
# Extract public key
$OPENSSL pkey -engine $ENGINE -in isara_hss_key.pem -pubout -out isara_hss_pub.pem
# Generata signature
$OPENSSL pkeyutl -engine $ENGINE -in testdata/message.txt -out hss_signature.bin -keyform ENGINE -inkey isara_hss_key.pem::hss_state.bin -sign

# Run the test case.
go run .

echo Passed
rm *.pem *.bin