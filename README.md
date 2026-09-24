# OWASP Kubernetes Top 10 (2025) Reference Implementation

A three-node [kind](https://kind.sigs.k8s.io/) cluster configured against the
[OWASP Kubernetes Top 10 (2025)](https://kubernetes-top10.owasp.org/2025/en/src/),
built to go with the talk *New OWASP Kubernetes Top 10 in Action and Explained*.

Every control here is configuration you can read. Nothing hides behind a tool
that "makes it secure". The point is to show what the built-in Kubernetes
objects look like when they are used properly.

```bash
./install.sh          # builds the cluster (~10 minutes)
./uninstall.sh        # tear it down
```

Once it is up, **[Seeing the controls](#seeing-the-controls)** has kubectl
commands for each of K01 to K10.

## Requirements

`kind`, `kubectl`, `helm` 3+, `docker`, `jq`, `openssl`, `curl`. The
[kubeapt](https://github.com/cenroq/kubeapt) binary downloads itself into
`bin/` if it is not already on your `PATH`.

Pinned versions: `kindest/node:v1.37.0`, Cilium 1.20.2, OpenBao chart 0.29.6,
Secrets Store CSI driver 1.6.1, and the kubeapt `owasp-kubernetes-top-ten`
bundle v2025.0.0 with 55 policies. The bundle name is the `KUBEAPT_BUNDLE`
variable at the top of `install.sh`. If it is not published, `install.sh` stops
instead of building a cluster with no admission control.

Cilium 1.20 is tested upstream against Kubernetes 1.33 to 1.36. If you hit CNI
trouble on a newer node image, drop `cluster/kind-config.yaml` to
`kindest/node:v1.36.1`. Nothing else in the repository depends on the version.

Nothing is published off the node. There are no NodePorts and no port mappings,
so use `kubectl port-forward` when you need to reach something.

**Build it before you need it.** A fresh cluster pulls roughly 3 GB, most of it
the Cilium agent image on all three nodes, and `install.sh` deletes and
recreates the cluster on every run, so a restart downloads everything again.
Until the Cilium operator image lands, the agents sit in *"Still waiting for
Cilium Operator to register CRDs"* and nothing else moves. The rollout wait is
set to 15 minutes to absorb that. A warm local Docker cache does not help the
nodes either: `kind load docker-image` cannot side-load from Docker's
containerd image store and fails with `content digest ... not found`.

## The ten

| | Risk | Implemented in | What you see |
|---|---|---|---|
| **K01** | Insecure Workload Configurations | `manifests/10-apps/star-wars.yaml` | no pod runs as root, privileged, with hostPath or without limits |
| **K02** | Overly Permissive Authorization | `manifests/20-rbac/star-wars-rbac.yaml` | `kubectl auth can-i` says no to every dangerous verb |
| **K03** | Secrets Management Failures | `cluster/encryption-config.yaml.tmpl`, `cluster/kind-config.yaml`, `manifests/60-secrets/` | etcd returns ciphertext, and the demo credential is not a Secret at all |
| **K04** | Lack Of Cluster Level Policy Enforcement | `install.sh` (kubeapt bundle), `manifests/40-admission/` | five deliberately broken workloads are all rejected |
| **K05** | Missing Network Segmentation Controls | `manifests/30-network/` | tiefighter may request landing, may not touch the exhaust port |
| **K06** | Overly Exposed Kubernetes Components | `cluster/kind-config.yaml` | no NodePort, kubelet returns 401, read-only port closed |
| **K07** | Misconfigured And Vulnerable Cluster Components | `cluster/kind-config.yaml` | profiling off, NodeRestriction on, per-controller credentials |
| **K08** | Cluster-To-Cloud Lateral Movement | `manifests/30-network/cilium-policies.yaml` | the metadata service is unreachable from a workload |
| **K09** | Broken Authentication Mechanisms | `cluster/authentication-config.yaml` | `/version` is 401, `/healthz` is 200, no pod holds a token |
| **K10** | Inadequate Logging And Monitoring | `cluster/audit-policy.yaml` | `pods/exec` is in the audit log, secret values are not |

## Seeing the controls

Every command below was run against this cluster, and the comments are the
output it gave. Set the context first:

```bash
kubectl config use-context kind-owasp-top10
```

### K01: Insecure Workload Configurations

```bash
# The container's own security context
kubectl -n star-wars get pod -l class=deathstar \
  -o jsonpath='{.items[0].spec.containers[0].securityContext}' | jq
# {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},
#  "privileged":false,"readOnlyRootFilesystem":true}

# And the pod level
kubectl -n star-wars get pod -l class=deathstar \
  -o jsonpath='{.items[0].spec.securityContext}' | jq
# {"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,
#  "seccompProfile":{"type":"RuntimeDefault"}}
```

### K02: Overly Permissive Authorization Configurations

```bash
SA=system:serviceaccount:star-wars:deathstar

kubectl auth can-i --list --as=$SA -n star-wars

# Each of the dangerous verbs from the talk - all "no"
kubectl auth can-i list secrets      -n star-wars --as=$SA
kubectl auth can-i create pods/exec  -n star-wars --as=$SA
kubectl auth can-i get nodes/proxy               --as=$SA
kubectl auth can-i impersonate users             --as=$SA
kubectl auth can-i create clusterrolebindings    --as=$SA
```

Two bindings are worth grepping for in any real cluster: `cluster-admin` bound
to a ServiceAccount, and any role bound to the `system:serviceaccounts` or
`system:authenticated` groups. The second one hands that role to every identity
in the cluster at once.

### K03: Secrets Management Failures

```bash
# There is no Secret object to steal - the credential is a file from OpenBao
kubectl -n star-wars get secrets
# No resources found in star-wars namespace.

kubectl -n star-wars get secretproviderclasspodstatuses \
  -o jsonpath='{.items[0].status.objects}'
# [{"id":"access-code","version":"..."}]

# Secrets that do exist are encrypted at rest. Write one, read it raw from etcd:
kubectl -n default create secret generic probe --from-literal=canary=TopSecretValue

kubectl -n kube-system exec etcd-owasp-top10-control-plane -- etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/probe
# k8s:enc:aescbc:v1:key1:<ciphertext> - and no "TopSecretValue" anywhere in it

kubectl -n default delete secret probe
```

`etcdctl` is not on the node. It lives inside the etcd static pod, and that
image has no shell, so the flags go straight to `etcdctl` as arguments.

Provider order is the thing to check. `identity` has to come **last**. Put it
first and every Secret is written in plaintext while the configuration still
looks like encryption is on.

### K04: Lack Of Cluster Level Policy Enforcement

```bash
kubeapt scan

# The bundle's policies, and the namespace that opted in
kubectl get validatingadmissionpolicy --no-headers | wc -l
kubectl get namespace star-wars -o jsonpath='{.metadata.labels}' | jq

# Submit a deliberately broken workload - admission refuses it
kubectl apply --dry-run=server \
  -f manifests/40-admission/violations/privileged-container.yaml
# Error ... ValidatingAdmissionPolicy ... denied request

ls manifests/40-admission/violations/   # four more, each breaking something else
```

The fixtures are bare Pods for a reason. A server-side dry run of a *Deployment*
is validated as a Deployment, so pod-scoped policies never run and it is
accepted. The rejection shows up later as a `FailedCreate` event on the
ReplicaSet.

### K05: Missing Network Segmentation Controls

```bash
kubectl -n star-wars get netpol
kubectl -n star-wars get ciliumnetworkpolicy

DEATHSTAR=deathstar.star-wars.svc.cluster.local

# An empire ship may request landing
kubectl -n star-wars exec deploy/tiefighter -- curl -s -XPOST $DEATHSTAR/v1/request-landing
# Ship landed

# The same ship may not touch the exhaust port - refused at L7 by Cilium,
# the request never reaches the application
kubectl -n star-wars exec deploy/tiefighter -- curl -s -XPUT $DEATHSTAR/v1/exhaust-port
# Access denied

# A rebel ship cannot reach it at all
kubectl -n star-wars exec deploy/xwing -- curl -s -m 5 -XPOST $DEATHSTAR/v1/request-landing
# command terminated with exit code 28   (timed out, dropped)
```

### K06: Overly Exposed Kubernetes Components

```bash
# Nothing is published off the node - every Service is ClusterIP
kubectl get svc -A

# The API server listens on loopback only
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
# https://127.0.0.1:<random port>

# The kubelet API needs credentials
docker exec owasp-top10-control-plane \
  curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:10250/pods
# 401

# The unauthenticated read-only port is closed
docker exec owasp-top10-control-plane curl -sS -m 3 http://127.0.0.1:10255/pods
# Failed to connect to 127.0.0.1 port 10255
```

### K07: Misconfigured And Vulnerable Cluster Components

```bash
docker exec owasp-top10-control-plane grep -E -- \
  '--(profiling|enable-admission-plugins|authorization-mode|tls-min-version)=' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
# --authorization-mode=Node,RBAC
# --enable-admission-plugins=NodeRestriction
# --profiling=false
# --tls-min-version=VersionTLS12

docker exec owasp-top10-control-plane grep -E -- \
  '--(profiling|use-service-account-credentials|bind-address)=' \
  /etc/kubernetes/manifests/kube-controller-manager.yaml

docker exec owasp-top10-control-plane grep -E -- '--(auto-tls|peer-auto-tls)=' \
  /etc/kubernetes/manifests/etcd.yaml

# kube-proxy is not running at all - Cilium replaces it
kubectl -n kube-system get ds kube-proxy
# Error from server (NotFound)
```

### K08: Cluster-To-Cloud Lateral Movement

```bash
kubectl get ciliumclusterwidenetworkpolicy deny-cloud-metadata -o yaml
```

Test it from a namespace with **no** NetworkPolicy. Doing this from `star-wars`
would prove nothing, because that namespace denies all egress anyway:

```bash
IMG=docker.io/curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6

kubectl -n default run metadata-check --image=$IMG --restart=Never --command -- sh -c 'sleep 300'
kubectl -n default wait --for=condition=Ready pod/metadata-check --timeout=90s

# Control: egress works in general
kubectl -n default exec metadata-check -- \
  curl -sk -m 5 -o /dev/null -w '%{http_code}\n' https://kubernetes.default.svc/healthz
# 200

# The metadata service is dropped
kubectl -n default exec metadata-check -- curl -s -m 5 http://169.254.169.254/
# command terminated with exit code 28

kubectl -n default delete pod metadata-check --now
```

Use the digest-pinned reference. The nodes already hold it, so the pod starts
without a registry round trip.

### K09: Broken Authentication Mechanisms

```bash
API=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

curl -sk -o /dev/null -w '%{http_code}\n' "$API/version"   # 401 - needs credentials
curl -sk -o /dev/null -w '%{http_code}\n' "$API/healthz"   # 200 - probes still work
curl -sk -o /dev/null -w '%{http_code}\n' "$API/api/v1/namespaces/default/pods"
# 401 - rejected at authentication, before RBAC is even consulted

# No pod carries a token it did not ask for
kubectl -n star-wars get pod -l class=deathstar \
  -o jsonpath='{.items[0].spec.automountServiceAccountToken}'   # false

# No long-lived ServiceAccount token Secrets anywhere
kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token
# No resources found

# The CSI driver instead mints a short-lived, audience-scoped token per mount
kubectl get csidriver secrets-store.csi.k8s.io -o jsonpath='{.spec.tokenRequests}'
# [{"audience":"openbao"}]
```

Getting a `401` rather than a `403` is the interesting part. With anonymous auth
restricted, the request never acquires an identity. Turn anonymous auth on fully
and the same paths answer `403` instead: authenticated as `system:anonymous`,
then stopped by RBAC.

### K10: Inadequate Logging And Monitoring

```bash
# Exec into a pod, then find it in the audit log
kubectl -n star-wars exec deploy/tiefighter -- true

docker exec owasp-top10-control-plane sh -c \
  "grep '\"subresource\":\"exec\"' /var/log/kubernetes/kube-apiserver-audit.log | tail -1" \
  | jq '{user: .user.username, verb, resource: .objectRef.resource,
         subresource: .objectRef.subresource, namespace: .objectRef.namespace,
         from: .sourceIPs[0], when: .requestReceivedTimestamp}'

# Secret access is recorded - but at Metadata level, so no values are logged
docker exec owasp-top10-control-plane sh -c \
  "grep -c '\"resource\":\"secrets\"' /var/log/kubernetes/kube-apiserver-audit.log"
```

A `level: None` rule covering `pods/exec`, `pods/attach`, `pods/portforward` and
the `proxy` subresources is the most effective way to blind an investigation,
and it is a common mistake because those rules look like noise reduction. This
policy logs all of them at `RequestResponse`.

## Notes on a few choices

**Admission control is kubeapt's `owasp-kubernetes-top-ten` bundle and nothing
else.** Its 55 policies are `ValidatingAdmissionPolicy` objects written in CEL,
so there is no Kyverno or OPA Gatekeeper deployment to run, secure and keep
alive. There is no Pod Security Admission either. One mechanism, one place to
look. The namespace opts in through a label the bundle defines, which is why
`install.sh` calls `kubeapt bundles enforce` instead of hard-coding a label into
the namespace manifest. Policies can roll out as `warn`, then `audit`, then
`enforce`.

**Admission is enforcing before any workload is applied.** If a manifest in this
repository violated the bundle, `install.sh` would fail instead of quietly
deploying it. The bundle goes in as `download`, then `enforce`, then `install`.
`manifests/40-admission/README.md` explains why that order matters and why the
violation fixtures are bare Pods rather than Deployments.

**Container images are pinned by digest as well as by tag.** A tag can be moved
to point at different content. A digest cannot. This is the one piece of supply
chain hygiene that costs nothing, and admission policies that require immutable
references will insist on it.

**Offline use.** `kubeapt bundles export` writes an installed bundle to a
tarball and `kubeapt bundles import` installs it from one. Useful before
presenting on conference wifi.

**K03 has two layers, and the second one is the point.** Encryption at rest
protects Secrets that exist. The deathstar's credential does not exist as a
Secret. OpenBao holds it and the Secrets Store CSI driver mounts it as a file,
so there is nothing in etcd to steal and nothing for an over-broad `list
secrets` rule to leak. The CSI driver authenticates as the workload with a
short-lived, audience-scoped token from the TokenRequest API, which is also why
the pod can set `automountServiceAccountToken: false`.

**K09 does not use `--anonymous-auth=false`.** That flag is mutually exclusive
with the structured `AuthenticationConfiguration`, and it also breaks the health
probes kubeadm and kind rely on while the cluster is coming up. The config file
allows anonymous requests on `/healthz`, `/readyz`, `/livez` and one ConfigMap,
so `/version` and every API path need credentials. That is the outcome the flag
was reaching for. The same file shows where an enterprise OIDC provider would
plug in, commented out, because a kind cluster has no issuer the API server can
reach.

Anonymous access is also allowed on
`/api/v1/namespaces/kube-public/configmaps/cluster-info`, and that exception is
worth understanding before deleting it. A joining node has no credentials yet,
so kubeadm's discovery reads that one ConfigMap anonymously and checks its JWS
signature against the bootstrap token. Remove the path and workers never join.
Matching is an exact string comparison, and authorization is still RBAC:
kubeadm's own `kubeadm:bootstrap-signer-clusterinfo` binding lets
`system:anonymous` GET that ConfigMap and nothing else, and its contents are the
API endpoint and the cluster CA certificate, both public by design. This is the
K09 challenge from the talk in miniature. Turning anonymous auth off is not one
switch, it is knowing what depends on it.

**Two kubelet settings are deliberately left out.** `protectKernelDefaults`,
because kind nodes share the host kernel and kubelet refuses to start, and
`serverTLSBootstrap`, because there is no CSR approver, so serving certificates
stay pending and `kubectl logs` breaks. A real hardened node running Talos or
Flatcar sets both.

**The star-wars demo is reimplemented rather than applied from its URL.** The
upstream images do not run under a hardened security context as they ship.
`quay.io/cilium/starwars` runs as root and its entrypoint hardcodes `--port 80`,
a privileged port, so the command is overridden to bind 8080 and the pod runs as
uid 65532. The image is a single scratch layer holding one static binary, so
`readOnlyRootFilesystem` costs nothing. `cilium/json-mock` is a Node-on-Debian
image whose json-server writes back to its database file, so the two client pods
run `curlimages/curl` instead. `runAsUser: 100` is mandatory there, because the
image's `USER` is the name `curl_user` and the kubelet cannot verify a name as
non-root. Pod labels are unchanged, so the L7 policy is the one from the Cilium
documentation.

## What the Top 10 does not cover

The list is about Kubernetes' built-in security. Two things sit outside it and
are out of scope here by design:

- **Service mesh**, meaning encryption in transit between workloads
- **Supply chain**, meaning what is inside the images in the first place
