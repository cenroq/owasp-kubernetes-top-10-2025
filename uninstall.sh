#!/bin/bash

set -uo pipefail

CLUSTER_NAME="owasp-top10"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

kind delete cluster --name "$CLUSTER_NAME"

rm -f "$SCRIPT_DIR/cluster/encryption-config.yaml"
rm -f "$SCRIPT_DIR/cluster/openbao-init.json"
rm -rf "$SCRIPT_DIR/bin"

echo "OWASP Kubernetes Top 10 reference cluster removed."
