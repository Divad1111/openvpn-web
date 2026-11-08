#!/usr/bin/env bash
# Exercise Easy-RSA in the actual built Agent container. No user CA data.
set -euo pipefail
image=openvpn-ce-control-agent:0.1.0
docker run --rm --entrypoint /bin/sh "$image" -ec '
  set -eu
  export EASYRSA_PKI=/tmp/ci-pki EASYRSA_BATCH=1 EASYRSA_REQ_CN=Test-CA EASYRSA_ALGO=ec EASYRSA_CURVE=secp384r1
  printf "%s\n" "ci-only-very-long-temporary-password" > /tmp/ca-pass
  chmod 600 /tmp/ca-pass
  /opt/easy-rsa/easyrsa --batch init-pki
  /opt/easy-rsa/easyrsa --batch --passout=file:/tmp/ca-pass build-ca
  /opt/easy-rsa/easyrsa --batch --passin=file:/tmp/ca-pass build-server-full server nopass
  /opt/easy-rsa/easyrsa --batch --passin=file:/tmp/ca-pass build-client-full testclient nopass
  /opt/easy-rsa/easyrsa --batch --passin=file:/tmp/ca-pass --days=365 gen-crl
  test -s "$EASYRSA_PKI/ca.crt"
  test -s "$EASYRSA_PKI/private/ca.key"
  test -s "$EASYRSA_PKI/issued/server.crt"
  test -s "$EASYRSA_PKI/private/testclient.key"
  test -s "$EASYRSA_PKI/crl.pem"
'
