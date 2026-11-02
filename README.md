# PRISM VPN CNF

Network Service Mesh inline network function source and Kubernetes manifests.

Requires Linux, Go 1.24+, Docker, and an existing Kubernetes/NSM/OVS environment.
Build locally with `./scripts/build_local_image.sh --no-import`.
Review the node selectors and image references in `k8s/` for your environment,
then deploy with `kubectl apply -k k8s`.
The build script produces a local `nse-ovs-vpn:dev` image; the manifests
reference prebuilt images. Update them to the image you built and make it
available to the target nodes before deploying.

Before deployment, apply `k8s/00-namespace.yaml`, then create the
`vpn-encrypt-wg` and `vpn-decrypt-wg` Secrets in namespace `nse-ovs-vpn`.
Each must contain `privatekey` (that endpoint's WireGuard private key) and
`peer_publickey` (the other endpoint's public key). Generate your own key pair
for each endpoint with WireGuard tooling; supply values using local files:

```sh
kubectl -n nse-ovs-vpn create secret generic vpn-encrypt-wg \
  --from-file=privatekey=/path/to/encrypt-privatekey \
  --from-file=peer_publickey=/path/to/decrypt-publickey
kubectl -n nse-ovs-vpn create secret generic vpn-decrypt-wg \
  --from-file=privatekey=/path/to/decrypt-privatekey \
  --from-file=peer_publickey=/path/to/encrypt-publickey
```

Keep these files outside the repository. Do not commit key material.

See `PROVENANCE.md` for the source snapshot.
