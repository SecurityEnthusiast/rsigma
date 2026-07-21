#!/usr/bin/env bash
# Generate a local CA, server cert (taxii.test + localhost), and client cert for mTLS tests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$ROOT/fixtures/certs"
mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/ca-key.pem"
CA_PEM="$CERT_DIR/ca.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
SERVER_PEM="$CERT_DIR/server.pem"
CLIENT_KEY="$CERT_DIR/client-key.pem"
CLIENT_PEM="$CERT_DIR/client.pem"

if [[ -f "$CA_PEM" ]]; then
  echo "Certificates already exist in $CERT_DIR (delete to regenerate)."
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$CA_KEY" -out "$CA_PEM" \
  -subj "/CN=RSTIX TAXII Live Test CA"

cat >"$CERT_DIR/server.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = taxii.test
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = taxii.test
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -newkey rsa:2048 -nodes -keyout "$SERVER_KEY" -out "$CERT_DIR/server.csr" \
  -config "$CERT_DIR/server.cnf"

openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_PEM" -days 825 -sha256 -extensions v3_req -extfile "$CERT_DIR/server.cnf"

openssl req -newkey rsa:2048 -nodes -keyout "$CLIENT_KEY" -out "$CERT_DIR/client.csr" \
  -subj "/CN=rstix-taxii-live-client"

openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_PEM" -days 825 -sha256

chmod 600 "$CA_KEY" "$SERVER_KEY" "$CLIENT_KEY"
echo "Wrote CA, server, and client material under $CERT_DIR"
