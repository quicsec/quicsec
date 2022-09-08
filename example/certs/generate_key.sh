#!/bin/bash

set -e

echo "Generating CA key and certificate:"
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ca.key -out ca.pem \
  -subj "/O=quic-go Certificate Authority/"

echo "Generating CSR"
openssl req -out server.csr -new -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/O=quic-go/"

echo "Sign certificate:"
openssl x509 -req -sha256 -days 3650 -in server.csr  -out server.pem \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:localhost,URI:spiffe://somedomain.foo.bar/foo/bar,URI:foo.bar")

# debug output the certificate
openssl x509 -noout -text -in server.pem

echo "Generating CSR"
openssl req -out client.csr -new -newkey rsa:2048 -nodes -keyout client.key \
  -subj "/O=quic-go/"

echo "Sign certificate:"
openssl x509 -req -sha256 -days 3650 -in client.csr  -out client.pem \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:localhost,URI:spiffe://anotherdomain.foo.bar/foo/bar,URI:foo.bar")

# debug output the certificate
openssl x509 -noout -text -in server.pem

# we don't need the CA key, the serial number and the CSR any more
#
#rm ca.key cert.csr ca.srl

