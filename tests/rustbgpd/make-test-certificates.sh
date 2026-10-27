#!/usr/bin/env bash
# Disposable test credentials, never use these identities in production.
# The unit test build caches them in its build directory, so they stay valid for 10 years.
set -euo pipefail
output=$1
hostname=${2:-localhost}
days=3650
mkdir -p "$output"
cd "$output"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" -subj '/CN=Test CA' -keyout ca.key -out ca.pem
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" -subj '/CN=Wrong CA' -keyout wrong-ca.key -out wrong-ca.pem
openssl req -newkey rsa:2048 -nodes -subj "/CN=$hostname" -keyout server.key -out server.csr
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$hostname" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days "$days" -extfile server.ext -out server.pem
# IP address SANs only, for targets given as literal addresses
openssl req -newkey rsa:2048 -nodes -subj '/CN=loopback' -keyout server-ip.key -out server-ip.csr
printf 'subjectAltName=IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\n' > server-ip.ext
openssl x509 -req -in server-ip.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days "$days" -extfile server-ip.ext -out server-ip.pem
openssl req -newkey rsa:2048 -nodes -subj '/CN=fastnetmon' -keyout client.key -out client.csr
printf 'subjectAltName=URI:rustbgpd://operator/fastnetmon\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days "$days" -extfile client.ext -out client.pem
rm ca.key wrong-ca.key ca.srl server.csr server-ip.csr client.csr server.ext server-ip.ext client.ext
