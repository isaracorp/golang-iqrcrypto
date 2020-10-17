# Golang Quantum-Safe Crypto

## Introduction
Quantum-safe crypto golang library. Includes Golang wrapper for the ISARA Radiate&trade; Quantum-Resistant Library 2.0 and implementation of ISARA Catalyst&trade; Agile Digital Certificate Technology.

This is a limited-functionality wrapper intended for use with [ISARA's Quantum-safe extension to Venafi's VCert](https://github.com/isaracorp/quantumsafe_vcert).

For more information about ISARA and our quantum-safe solutions, visit www.isara.com.

## Building

This wrapper requires the [ISARA toolkit](https://www.isara.com/toolkit/2/doc/guide/guide.html).  Please contact info@isara.com for more information.

1. Extract the toolkit.  In the rest of these instructions we'll assume it has been extracted to `~/iqr_toolkit`.
2. Set the environment variable so the wrapper can find the toolkit.
```sh
export IQR_TOOLKIT_PATH=~/iqr_toolkit # Use your actual iqr toolkit path
```
3. Build and run tests
```sh
cd golang-iqrcrypto
make
```

If `IQR_TOOLKIT_PATH` is not set, the wrapper will still build but any functions that rely on the ISARA toolkit will return an error.

## OpenSSL Connector Compatibility Tests

To run the OpenSSL Connector compatibility tests you need [ISARA Catalyst OpenSSL Connector 2.0](https://www.isara.com/openssl/2.0/).  Please contact info@isara.com for more information.

1. Using the OpenSSL Connector guide, build and install OpenSSL Connector.  In the rest of the instructions we'll assume it has been installed to `/usr/local/isara_ssl`.
2. Set the environment so the tests can find the toolkit and OpenSSL Connector
```sh
export IQR_TOOLKIT_PATH=~/iqr_toolkit # Use your actual iqr toolkit path
export OPENSSL=/usr/local/isara_ssl/bin/openssl
export ENGINE=/usr/local/isara_ssl/lib/engines/libiqre_engine.so
```
3. Run tests
```sh
cd golang-iqrcrypto/compatibility_test/certificate
./test.sh
cd ../dilithium
./test.sh
cd ../hss
./test.sh
```

## License

See the `LICENSE` file for details:

>Copyright &copy; 2020, ISARA Corporation
>
>Licensed under the Apache License, Version 2.0 (the "License");
>you may not use this file except in compliance with the License.
>You may obtain a copy of the License at
>
>http://www.apache.org/licenses/LICENSE-2.0
>
>Unless required by applicable law or agreed to in writing, software
>distributed under the License is distributed on an "AS IS" BASIS,
>WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>See the License for the specific language governing permissions and
>limitations under the License.

### Trademarks

ISARA Radiate&trade; and ISARA Catalyst&trade; are trademarks of ISARA Corporation.

### Patent Information

Portions of this software are covered by US Patent
[10,425,401](http://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PALL&p=1&u=%2Fnetahtml%2FPTO%2Fsrchnum.htm&r=1&f=G&l=50&s1=10,425,401.PN.&OS=PN/10,425,401&RS=PN/10,425,401[10,425,401])
