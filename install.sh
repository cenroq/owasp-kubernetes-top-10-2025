#!/bin/bash

set -euo pipefail

CLUSTER_NAME="owasp-top10"
CILIUM_VERSION="1.20.2"
CSI_DRIVER_VERSION="1.6.1"
OPENBAO_VERSION="0.29.6"
KUBEAPT_VERSION="v2.1.0"

KUBEAPT_BUNDLE="owasp-kubernetes-top-ten"

OPENBAO_AUDIENCE="openbao"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v kubeapt >/dev/null 2>&1; then
  KUBEAPT="kubeapt"
else
  KUBEAPT_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  KUBEAPT_ARCH="$(uname -m)"
  case "$KUBEAPT_ARCH" in
    x86_64) KUBEAPT_ARCH="amd64" ;;
    aarch64) KUBEAPT_ARCH="arm64" ;;
  esac
  echo "==> Downloading kubeapt $KUBEAPT_VERSION ($KUBEAPT_OS/$KUBEAPT_ARCH)"
  mkdir -p bin
  curl -sSfL -o bin/kubeapt \
    "https://github.com/cenroq/kubeapt/releases/download/$KUBEAPT_VERSION/kubeapt-$KUBEAPT_OS-$KUBEAPT_ARCH"
  chmod +x bin/kubeapt
  KUBEAPT="$SCRIPT_DIR/bin/kubeapt"
fi

# K04
echo "==> Checking that the $KUBEAPT_BUNDLE bundle is published"
BUNDLE_LIST="$("$KUBEAPT" bundles list 2>&1)" || true
if ! printf '%s\n' "$BUNDLE_LIST" | grep -q "$KUBEAPT_BUNDLE"; then
  echo
  echo "ERROR: kubeapt does not offer a bundle named '$KUBEAPT_BUNDLE'."
  echo
  echo "This cluster uses that bundle as its only admission control mechanism,"
  echo "so there is nothing to fall back to. Fix the KUBEAPT_BUNDLE variable at"
  echo "the top of this script, or wait until the bundle is published."
  echo
  echo "kubeapt bundles list reported:"
  printf '%s\n' "$BUNDLE_LIST" | sed 's/^/    /'
  exit 1
fi

# K03
echo "==> Generating the etcd encryption key"
sed "s|__KEY__|$(openssl rand -base64 32)|" \
  cluster/encryption-config.yaml.tmpl > cluster/encryption-config.yaml
chmod 600 cluster/encryption-config.yaml

kind delete cluster --name "$CLUSTER_NAME"

kind create cluster --name "$CLUSTER_NAME" --config cluster/kind-config.yaml

# K05
echo "==> Installing Cilium $CILIUM_VERSION"
helm repo add cilium https://helm.cilium.io/ --force-update
helm install cilium cilium/cilium --version "$CILIUM_VERSION" \
  --namespace kube-system \
  --set ipam.mode=kubernetes \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="$CLUSTER_NAME-control-plane" \
  --set k8sServicePort=6443 \
  --set image.pullPolicy=IfNotPresent \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=false

echo "==> Waiting for Cilium"
kubectl -n kube-system rollout status daemonset/cilium --timeout=15m
kubectl -n kube-system rollout status deployment/cilium-operator --timeout=15m
kubectl -n kube-system rollout status daemonset/cilium-envoy --timeout=15m \
  || echo "    no standalone cilium-envoy DaemonSet - L7 runs inside the agent"
kubectl wait --for=condition=Ready nodes --all --timeout=15m

kubectl apply -f manifests/00-namespaces.yaml

# K04
echo "==> Installing the $KUBEAPT_BUNDLE admission bundle"
"$KUBEAPT" bundles download "$KUBEAPT_BUNDLE"
"$KUBEAPT" bundles enforce "$KUBEAPT_BUNDLE" -n star-wars --overwrite
"$KUBEAPT" bundles install "$KUBEAPT_BUNDLE"

# K03, K09
echo "==> Installing the Secrets Store CSI driver $CSI_DRIVER_VERSION"
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts --force-update
helm install secrets-store-csi-driver \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --version "$CSI_DRIVER_VERSION" \
  --namespace kube-system \
  --set syncSecret.enabled=false \
  --set enableSecretRotation=true \
  --set "tokenRequests[0].audience=$OPENBAO_AUDIENCE" \
  --wait

# K03
echo "==> Installing OpenBao $OPENBAO_VERSION"
helm repo add openbao https://openbao.github.io/openbao-helm --force-update
helm install openbao openbao/openbao --version "$OPENBAO_VERSION" \
  --namespace openbao \
  --set server.standalone.enabled=true \
  --set server.dataStorage.enabled=true \
  --set server.dataStorage.size=1Gi \
  --set injector.enabled=false \
  --set ui.enabled=false \
  --set csi.enabled=true \
  --set csi.agent.enabled=false \
  --set csi.daemonSet.providersDir=/var/run/secrets-store-csi-providers

echo "==> Waiting for OpenBao to start"
kubectl -n openbao wait --for=jsonpath='{.status.phase}'=Running pod/openbao-0 --timeout=5m

echo "==> Initialising and unsealing OpenBao"
kubectl -n openbao exec openbao-0 -- \
  bao operator init -key-shares=1 -key-threshold=1 -format=json > cluster/openbao-init.json
chmod 600 cluster/openbao-init.json
OPENBAO_UNSEAL_KEY="$(jq -r '.unseal_keys_b64[0]' cluster/openbao-init.json)"
OPENBAO_ROOT_TOKEN="$(jq -r '.root_token' cluster/openbao-init.json)"
kubectl -n openbao exec openbao-0 -- bao operator unseal "$OPENBAO_UNSEAL_KEY" >/dev/null
kubectl -n openbao wait --for=condition=Ready pod/openbao-0 --timeout=5m

# K03, K09
echo "==> Seeding the OpenBao secret and Kubernetes auth role"
kubectl -n openbao exec -i openbao-0 -- sh -s <<EOF
set -e
export BAO_ADDR=http://127.0.0.1:8200
export BAO_TOKEN="$OPENBAO_ROOT_TOKEN"

bao secrets enable -path=secret kv-v2
bao kv put secret/star-wars/deathstar access-code="\$(head -c 24 /dev/urandom | base64)"

bao auth enable kubernetes
bao write auth/kubernetes/config \
  kubernetes_host="https://\$KUBERNETES_SERVICE_HOST:\$KUBERNETES_SERVICE_PORT"

bao policy write deathstar - <<'POLICY'
path "secret/data/star-wars/deathstar" {
  capabilities = ["read"]
}
POLICY

bao write auth/kubernetes/role/deathstar \
  bound_service_account_names=deathstar \
  bound_service_account_namespaces=star-wars \
  audience="$OPENBAO_AUDIENCE" \
  policies=deathstar \
  ttl=20m
EOF

for image in \
  quay.io/cilium/starwars:v2.1 \
  docker.io/curlimages/curl:8.16.0 ; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
    kind load docker-image --name "$CLUSTER_NAME" "$image" \
      || echo "    could not side-load $image - the nodes will pull it"
done

# K02
kubectl apply -f manifests/20-rbac/

# K09
for namespace in star-wars openbao ; do
  kubectl -n "$namespace" patch serviceaccount default \
    -p '{"automountServiceAccountToken":false}'
done

# K03
kubectl apply -f manifests/60-secrets/

# K01
kubectl apply -f manifests/10-apps/

# K05, K08
kubectl apply -f manifests/30-network/

echo "==> Waiting for the star-wars workloads"
kubectl -n star-wars rollout status deployment/deathstar --timeout=5m
kubectl -n star-wars rollout status deployment/tiefighter --timeout=5m
kubectl -n star-wars rollout status deployment/xwing --timeout=5m

cat <<'BANNER'
================================================================
 OWASP Kubernetes Top 10 (2025) reference cluster is up.

   kubectl config use-context kind-owasp-top10

   ./uninstall.sh     tear it down

 README.md has kubectl commands per OWASP control.

 Nothing is published off the node. Use kubectl port-forward.
================================================================
BANNER
