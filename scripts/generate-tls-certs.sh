#!/usr/bin/env bash
set -euo pipefail

# Generates a local self-signed certificate for testing the HTTPS reverse
# proxy path. NOT for production use — browsers/clients will warn about it,
# which is expected for a self-signed cert.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/server.key" \
  -out "$DIR/server.cert" \
  -days 365 \
  -subj "/C=US/ST=Local/L=Local/O=AutonomousGateway/CN=localhost"

echo "Certs written to $DIR"
echo "  $DIR/server.key"
echo "  $DIR/server.cert"
