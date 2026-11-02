#!/usr/bin/env bash
set -euo pipefail

NS_NAMESPACE="${NS_NAMESPACE:-nse-ovs-vpn}"
ENCRYPT_POD_PREFIX="${ENCRYPT_POD_PREFIX:-nse-ovs-vpn-encrypt-}"
DECRYPT_POD_PREFIX="${DECRYPT_POD_PREFIX:-nse-ovs-vpn-decrypt-}"
VPN_CONTAINER="${VPN_CONTAINER:-nse}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"
KUBECTL="${KUBECTL:-kubectl}"

run_kubectl() {
  "${KUBECTL}" "$@"
}

get_running_pod_by_prefix() {
  local namespace="$1"
  local prefix="$2"
  run_kubectl get pods -n "${namespace}" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase \
    | awk -v prefix="${prefix}" '$1 ~ ("^" prefix) && $2 == "Running" { print $1; exit }'
}

pod_has_session_artifacts() {
  local pod_name="$1"
  run_kubectl exec -n "${NS_NAMESPACE}" "${pod_name}" -c "${VPN_CONTAINER}" -- sh -eu -c '
    if ip link show dev wg0 >/dev/null 2>&1; then
      exit 0
    fi
    if ip -o link show | awk -F": " '\''{print $2}'\'' | awk '\''{print $1}'\'' | grep -Eq "^(nse-ovs-vp-|nsmbr)"; then
      exit 0
    fi
    exit 1
  '
}

encrypt_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${ENCRYPT_POD_PREFIX}")"
decrypt_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${DECRYPT_POD_PREFIX}")"
[[ -n "${encrypt_pod}" ]] || { echo "encrypt pod not found" >&2; exit 1; }
[[ -n "${decrypt_pod}" ]] || { echo "decrypt pod not found" >&2; exit 1; }

deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))
while (( SECONDS < deadline )); do
  if ! pod_has_session_artifacts "${encrypt_pod}" && ! pod_has_session_artifacts "${decrypt_pod}"; then
    echo "VPN cleanup check: PASS"
    exit 0
  fi
  sleep "${POLL_INTERVAL_SECONDS}"
done

echo "vpn cleanup timed out" >&2
exit 1
