# K04: Lack Of Cluster Level Policy Enforcement

There are no policy manifests in this directory, and that is deliberate.

Admission control for this cluster is the kubeapt `owasp-kubernetes-top-ten`
bundle (v2025.0.0): 55 ValidatingAdmissionPolicies written in CEL, installed and
switched to enforce by `install.sh`. No Kyverno, no OPA Gatekeeper, and no Pod
Security Admission.

The namespace opt-in label is defined by the bundle manifest, not by us, which
is why no label is hard-coded in `manifests/00-namespaces.yaml`. For this bundle
it resolves to `owasp.org/enforce: enabled`.

## Install order

`install.sh` runs `download`, then `enforce`, then `install` - in that order,
and the order is load-bearing:

```bash
kubeapt bundles download owasp-kubernetes-top-ten          # local cache only
kubeapt bundles enforce  owasp-kubernetes-top-ten -n star-wars
kubeapt bundles install  owasp-kubernetes-top-ten          # activate policies
```

`download` changes nothing in the cluster, but it is what teaches kubeapt the
bundle's opt-in label key. Labelling the namespace while no policy is active yet
means the patch cannot be rejected.

Install first and a bundle that also constrains `Namespace` objects will deny
the same patch that opts the namespace into it. That is a chicken-and-egg which
is easy to hit and confusing to debug.

## The violation fixtures

`violations/` holds workloads the bundle should reject. They are never applied
by `install.sh` - they exist to be shown. Submit any of them to see a policy
fire:

```bash
kubectl apply --dry-run=server -f manifests/40-admission/violations/hostpath-volume.yaml
```

They are bare `Pod` objects on purpose. A server-side dry run of a `Deployment`
is validated as a *Deployment*; no Pod is ever created, so pod-scoped policies
never run and the Deployment is happily accepted. The rejection only happens
later, out of band, when the ReplicaSet controller tries to create the Pod - and
it surfaces as a `FailedCreate` event rather than as an error from `kubectl`.
Worth knowing before you demo a rejection with a Deployment and nothing happens.
