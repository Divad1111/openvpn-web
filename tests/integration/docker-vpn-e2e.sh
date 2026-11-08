#!/usr/bin/env bash
# Linux Docker-only integration: OpenVPN CE 2.7.9 TCP client handshake and
# certificate revocation in isolated Docker network. Uses fresh test PKI.
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then echo 'SKIP: docker CLI unavailable' >&2; exit 77; fi
if [[ ! -c /dev/net/tun ]]; then echo 'SKIP: /dev/net/tun unavailable; handshake NOT verified' >&2; exit 77; fi
agent_image=openvpn-ce-control-agent:0.1.0
vpn_image=openvpn-ce:2.7.9-local
suffix="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
network="ovpn-e2e-$suffix"; server="ovpn-server-$suffix"; client="ovpn-client-$suffix"
tmp="$(mktemp -d)"
cleanup() {
 docker rm -f "$client" "$server" >/dev/null 2>&1 || true
 docker network rm "$network" >/dev/null 2>&1 || true
 # Test-only PKI files can be owned by container root; remove them via Docker.
 docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /bin/sh "$agent_image" -ec 'rm -rf /test/pki /test/pass /test/passout /test/tls-crypt.key /test/server.conf /test/client.conf' >/dev/null 2>&1 || true
 rm -rf "$tmp" || true
}
trap cleanup EXIT
chmod 700 "$tmp"
mkdir -m 700 "$tmp/pki"
docker network create "$network" >/dev/null
# The test-only CA passphrase is never used for real deployments.
docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /bin/sh "$agent_image" -ec '
 set -eu
 export EASYRSA_PKI=/test/pki EASYRSA_BATCH=1 EASYRSA_REQ_CN=Test-Only-CA EASYRSA_ALGO=ec EASYRSA_CURVE=secp384r1
 printf "%s\n" "test-only-do-not-reuse-ca-passphrase" > /test/pass
 cp /test/pass /test/passout
 chmod 600 /test/pass /test/passout
 /opt/easy-rsa/easyrsa --batch init-pki
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass --passout=file:/test/passout build-ca
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass build-server-full server nopass
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass build-client-full e2eclient nopass
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass --days=365 gen-crl
'
docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /usr/local/sbin/openvpn "$vpn_image" --genkey tls-crypt /test/tls-crypt.key
cat > "$tmp/server.conf" <<'CONF'
port 1194
proto tcp-server
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca /test/pki/ca.crt
cert /test/pki/issued/server.crt
key /test/pki/private/server.key
crl-verify /test/pki/crl.pem
tls-crypt /test/tls-crypt.key
dh none
data-ciphers AES-256-GCM:AES-128-GCM
verify-client-cert require
status /tmp/status.csv 2
status-version 3
verb 3
CONF
cat > "$tmp/client.conf" <<CONF
client
proto tcp-client
dev tun
remote $server 1194
nobind
resolv-retry 3
ca /test/pki/ca.crt
cert /test/pki/issued/e2eclient.crt
key /test/pki/private/e2eclient.key
tls-crypt /test/tls-crypt.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
CONF
# Bind-mounted test PKI must be readable by the root:10001 runtime process,
# which has CAP_DAC_OVERRIDE deliberately removed. Directories are group-rx,
# all test-only files are group-readable, and the owning Runner retains access.
docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /bin/sh "$agent_image" -ec '
 chgrp -R 10001 /test
 find /test -type d -exec chmod 0750 {} +
 find /test -type f -exec chmod 0640 {} +
'
# Both VPN containers have only NET_ADMIN and TUN, not --privileged.
docker run -d --name "$server" --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
 --device /dev/net/tun -v "$tmp:/test:ro" --entrypoint /usr/local/sbin/openvpn \
 "$vpn_image" --config /test/server.conf >/dev/null
started=0
for _ in $(seq 1 35); do
 if docker logs "$server" 2>&1 | grep -q 'Initialization Sequence Completed'; then started=1; break; fi
 sleep 1
done
if [[ "$started" != 1 ]]; then echo 'Server failed to initialize:' >&2; docker logs "$server" >&2; exit 1; fi
docker run -d --name "$client" --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
 --device /dev/net/tun -v "$tmp:/test:ro" --entrypoint /usr/local/sbin/openvpn \
 "$vpn_image" --config /test/client.conf >/dev/null
connected=0
for _ in $(seq 1 35); do
 if docker logs "$client" 2>&1 | grep -q 'Initialization Sequence Completed'; then connected=1; break; fi
 sleep 1
done
if [[ "$connected" != 1 ]]; then echo 'Client TCP/TLS handshake failed:' >&2;docker logs "$server" >&2;docker logs "$client" >&2;exit 1;fi
# Revoke the client certificate and recreate CRL. Ensure a new handshake fails.
docker rm -f "$client" >/dev/null
docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /bin/sh "$agent_image" -ec '
 set -eu
 export EASYRSA_PKI=/test/pki EASYRSA_BATCH=1 EASYRSA_REQ_CN=Test-Only-CA
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass revoke-issued e2eclient
 /opt/easy-rsa/easyrsa --batch --passin=file:/test/pass --days=365 gen-crl
'
# Easy-RSA replaced the CRL file with a new root-owned inode; restore the
# intended read group before testing revocation against a least-privilege server.
docker run --rm --user 0:0 -v "$tmp:/test" --entrypoint /bin/sh "$agent_image" \
 -ec 'chgrp 10001 /test/pki/crl.pem; chmod 0640 /test/pki/crl.pem'
docker run -d --name "$client" --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
 --device /dev/net/tun -v "$tmp:/test:ro" --entrypoint /usr/local/sbin/openvpn \
 "$vpn_image" --config /test/client.conf >/dev/null
sleep 12
if docker logs "$client" 2>&1 | grep -q 'Initialization Sequence Completed'; then
 echo 'SECURITY FAILURE: revoked certificate connected' >&2
 docker logs "$server" >&2; docker logs "$client" >&2
 exit 1
fi
if ! docker logs "$server" 2>&1 | grep -qiE 'certificate revoked|CRL'; then
 echo 'WARNING: revoked handshake did not succeed, but OpenVPN server log did not explicitly confirm CRL rejection' >&2
fi
echo 'PASS: OpenVPN CE 2.7.9 TCP/TLS handshake succeeded, then revoked certificate was rejected on reconnect'