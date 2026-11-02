#!/usr/bin/env bash
set -euo pipefail

NS_NAMESPACE="${NS_NAMESPACE:-nse-ovs-vpn}"
CLIENT_POD_PREFIX="${CLIENT_POD_PREFIX:-nsc-ovs-client-}"
ENCRYPT_POD_PREFIX="${ENCRYPT_POD_PREFIX:-nse-ovs-vpn-encrypt-}"
DECRYPT_POD_PREFIX="${DECRYPT_POD_PREFIX:-nse-ovs-vpn-decrypt-}"
SERVER_POD_PREFIX="${SERVER_POD_PREFIX:-nse-ovs-server-}"
CLIENT_CONTAINER="${CLIENT_CONTAINER:-client}"
VPN_CONTAINER="${VPN_CONTAINER:-nse}"
SERVER_CONTAINER="${SERVER_CONTAINER:-server}"
CLIENT_IFACE="${CLIENT_IFACE:-nsm-1}"
TARGET_IP="${TARGET_IP:-172.16.1.100}"
IPERF_PORT="${IPERF_PORT:-5201}"
TCP_SECONDS="${TCP_SECONDS:-5}"
UDP_SECONDS="${UDP_SECONDS:-5}"
UDP_BANDWIDTH="${UDP_BANDWIDTH:-5G}"
RUN_PING_CHECK="${RUN_PING_CHECK:-false}"
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

pod_sh() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local command="$4"
  run_kubectl exec -n "${namespace}" "${pod_name}" -c "${container_name}" -- sh -eu -c "${command}"
}

client_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${CLIENT_POD_PREFIX}")"
encrypt_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${ENCRYPT_POD_PREFIX}")"
decrypt_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${DECRYPT_POD_PREFIX}")"
server_pod="$(get_running_pod_by_prefix "${NS_NAMESPACE}" "${SERVER_POD_PREFIX}")"

[[ -n "${client_pod}" ]] || { echo "client pod not found" >&2; exit 1; }
[[ -n "${encrypt_pod}" ]] || { echo "encrypt pod not found" >&2; exit 1; }
[[ -n "${decrypt_pod}" ]] || { echo "decrypt pod not found" >&2; exit 1; }
[[ -n "${server_pod}" ]] || { echo "server pod not found" >&2; exit 1; }

echo "== Pods =="
echo "client  : ${client_pod}"
echo "encrypt : ${encrypt_pod}"
echo "decrypt : ${decrypt_pod}"
echo "server  : ${server_pod}"

echo
echo "== Client Interface =="
pod_sh "${NS_NAMESPACE}" "${client_pod}" "${CLIENT_CONTAINER}" "ip -o -4 addr show dev ${CLIENT_IFACE}; ip route"

echo
echo "== Encrypt Pod =="
pod_sh "${NS_NAMESPACE}" "${encrypt_pod}" "${VPN_CONTAINER}" "ip -o -4 addr show; ip route"

echo
echo "== Decrypt Pod =="
pod_sh "${NS_NAMESPACE}" "${decrypt_pod}" "${VPN_CONTAINER}" "ip -o -4 addr show; ip route"

echo
echo "== Server Pod =="
pod_sh "${NS_NAMESPACE}" "${server_pod}" "${SERVER_CONTAINER}" "ip -o -4 addr show; ip route"

echo
echo "== WireGuard Show: Encrypt =="
run_kubectl exec -n "${NS_NAMESPACE}" "${encrypt_pod}" -c "${VPN_CONTAINER}" -- wg show || true

echo
echo "== WireGuard Show: Decrypt =="
run_kubectl exec -n "${NS_NAMESPACE}" "${decrypt_pod}" -c "${VPN_CONTAINER}" -- wg show || true

if [[ "${RUN_PING_CHECK}" == "true" ]]; then
  echo
  echo "== Ping =="
  run_kubectl exec -n "${NS_NAMESPACE}" "${client_pod}" -c "${CLIENT_CONTAINER}" -- \
    ping -c 2 -W 1 "${TARGET_IP}"
else
  echo
  echo "== Ping =="
  echo "skipped by default: V1 only proxies ${IPERF_PORT}/tcp and ${IPERF_PORT}/udp, not generic ICMP"
fi

echo
echo "== iperf3 TCP =="
run_kubectl exec -n "${NS_NAMESPACE}" "${client_pod}" -c "${CLIENT_CONTAINER}" -- \
  iperf3 -c "${TARGET_IP}" -p "${IPERF_PORT}" -t "${TCP_SECONDS}"

echo
echo "== iperf3 UDP =="
run_kubectl exec -n "${NS_NAMESPACE}" "${client_pod}" -c "${CLIENT_CONTAINER}" -- \
  iperf3 -u -c "${TARGET_IP}" -p "${IPERF_PORT}" -b "${UDP_BANDWIDTH}" -t "${UDP_SECONDS}"
