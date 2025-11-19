#!/usr/bin/env bash
# Section 3 - VLANs & Trunk/Access Labs (Two-Server Labs, role 1/2)
# Labs:
# 1) Creating VLAN Interfaces (CONFIG): vlan10 on ens4 + static IP (role-based)
# 2) Creating VLAN Interfaces (CONFIG): vlan20 on ens4 + static IP (role-based)
# 3) Creating VLAN Interfaces (TROUBLESHOOT): validate vlan10/vlan20 existence, IDs, IPs, NM status
# 4) Trunk Ports (CONFIG): vlan50 & vlan60 active on ens4 (+ optional peer pings)   <-- UPDATED
# 5) Access Ports (CONFIG): untagged access connection on ens4 + static IP (role-based)
# 6) Trunk/Access (TROUBLESHOOT): detect mode & validate expected state (+ optional peer pings)

# ---- Run-as-root check BEFORE set -e / trap ----
if (( EUID != 0 )); then
  echo -e "\e[33m[!] Please run as root: sudo $0 $*\e[0m"
  exit 1
fi

# Strict mode + friendly trap
if [[ -n "${LABS_DEBUG:-}" ]]; then set -x; fi
set -Eeuo pipefail
trap 'rc=$?; if [[ $rc -ne 0 ]]; then
  echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2
fi' ERR

# ===== User variables (10.10.20.0/24) =====
PREFIX="24"
# VLAN 10 / 20 (Lab 1/2 + Lab 3 troubleshoot)
V10_S1_IP="10.10.20.21"; V10_S2_IP="10.10.20.22"
V20_S1_IP="10.10.20.31"; V20_S2_IP="10.10.20.32"
# VLAN 50 / 60 (Lab 4 trunk UPDATED)
V50_S1_IP="10.10.20.51"; V50_S2_IP="10.10.20.52"
V60_S1_IP="10.10.20.61"; V60_S2_IP="10.10.20.62"
# Access (untagged)
ACC_S1_IP="10.10.20.41"; ACC_S2_IP="10.10.20.42"

# Optional peer pings
PING_PEER="${S3_PING:-1}"
PING_COUNT="${S3_PING_COUNT:-2}"
PING_TIMEOUT="${S3_PING_TIMEOUT:-1}"

# ===== Paths / State =====
LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"
NETPLAN_DIR="/etc/netplan"
S3_NETPLAN_FILE="${NETPLAN_DIR}/10-section3-nm.yaml"
NM_CONF_DIR="/etc/NetworkManager/conf.d"

# Connection names
NM_CONN_V10="s3-vlan10"
NM_CONN_V20="s3-vlan20"
NM_CONN_V50="s3-vlan50"   # NEW
NM_CONN_V60="s3-vlan60"   # NEW
NM_CONN_ACC="s3-access"

# Base interface is always ens4 in these labs
BASE_IF="ens4"

# ===== Colors =====
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"; WARN="${YELLOW}[!]${NC}"

# ===== Helpers =====
q(){ "$@" >/dev/null 2>&1 || true; }
mkdirs(){ mkdir -p "$LAB_ROOT"; }
save_state(){
  local k="$1" v="$2"
  mkdirs; touch "$STATE_FILE"
  if grep -q "^${k}=" "$STATE_FILE" 2>/dev/null; then
    sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE"
  else
    echo "${k}=${v}" >>"$STATE_FILE"
  fi
}
get_state(){
  local k="$1"
  [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
  grep "^${k}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true
}
nm_is_active(){ command -v nmcli >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; }
write_file(){ local path="$1" mode="$2"; umask 022; cat >"$path"; chmod "$mode" "$path" || true; chown root:root "$path" || true; }

# --- Ensure NM & renderer: fix "device is unmanaged"
nm_require_and_ensure_renderer(){
  # Install & start NM
  if ! command -v nmcli >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y network-manager
  fi
  q systemctl enable --now NetworkManager
  if ! nm_is_active; then
    echo -e "${FAIL} NetworkManager is not active. Start it: sudo systemctl enable --now NetworkManager"
    exit 2
  fi

  # Netplan -> NetworkManager renderer
  write_file "${S3_NETPLAN_FILE}" 0600 <<'YAML'
network:
  version: 2
  renderer: NetworkManager
YAML
  q netplan generate
  q netplan apply

  # NM conf.d overrides to ensure devices are managed
  mkdir -p "${NM_CONF_DIR}"
  write_file "${NM_CONF_DIR}/10-globally-managed-devices.conf" 0644 <<'INI'
[keyfile]
unmanaged-devices=
INI
  write_file "${NM_CONF_DIR}/10-ifupdown-managed.conf" 0644 <<'INI'
[ifupdown]
managed=true
INI
  q systemctl restart NetworkManager
  sleep 1
}

# --- NM device helpers
peer_ip(){ local role="$1" s1="$2" s2="$3"; [[ "$role" == "1" ]] && echo "$s2" || echo "$s1"; }
ping_on_iface(){
  local ifc="$1" peer="$2" lbl="$3"
  if [[ "${PING_PEER}" == "1" ]] && command -v ping >/dev/null 2>&1; then
    if ping -I "$ifc" -c "${PING_COUNT}" -W "${PING_TIMEOUT}" "$peer" >/dev/null 2>&1; then
      echo -e "${OK} Peer reachable (${lbl} -> ${peer})"
    else
      echo -e "${WARN} Peer not reachable (${lbl} -> ${peer}); check mode/subnet/cable/VLAN tag)"
    fi
  else
    echo -e "${INFO} Skipping ping (${lbl}); enable with S3_PING=1"
  fi
}

# --- Check reporting
good(){ echo -e "${OK} $*"; }
miss(){ echo -e "${FAIL} $*"; FAILS=$((FAILS+1)); }
begin_check(){ FAILS=0; }
end_check(){
  if [[ ${FAILS:-0} -eq 0 ]]; then
    echo -e "${OK} All checks passed"
  else
    echo -e "${FAIL} ${FAILS} issue(s) found"
    exit 4
  fi
}

# ===== VLAN ID check (robust) =====
check_vlan_id(){
  local ifname="$1" expect="$2" conn_name="$3"
  local ok=0
  # ip(8) formatting varies; accept "vlan id 50" or "id 50"
  if ip -d link show "$ifname" 2>/dev/null | grep -Eiq "(vlan[[:space:]]+id[[:space:]]+${expect})|(^|[[:space:]])id[[:space:]]+${expect}([[:space:]]|$)"; then
    ok=1
  fi
  # NM profile property is authoritative
  local nm_id
  nm_id="$(nmcli -g vlan.id connection show "$conn_name" 2>/dev/null || true)"
  if [[ -n "$nm_id" ]] && [[ "$nm_id" == "$expect" ]]; then
    ok=1
  fi
  [[ $ok -eq 1 ]]
}

# ===== Summaries =====
summary_for_lab(){
  local lab="$1"
  case "$lab" in
    1)
      cat <<EOF
${BOLD}Summary — Lab 1 (Create VLAN 10 on ${BASE_IF})${NC}
- Switch Netplan to NetworkManager; ensure NM manages devices.
- Create 'vlan10' (id 10) on ${BASE_IF}.
- Assign role-based IPv4: 1 -> ${V10_S1_IP}/${PREFIX}, 2 -> ${V10_S2_IP}/${PREFIX}.
EOF
      ;;
    2)
      cat <<EOF
${BOLD}Summary — Lab 2 (Create VLAN 20 on ${BASE_IF})${NC}
- Switch Netplan to NetworkManager; ensure NM manages devices.
- Create 'vlan20' (id 20) on ${BASE_IF}.
- Assign role-based IPv4: 1 -> ${V20_S1_IP}/${PREFIX}, 2 -> ${V20_S2_IP}/${PREFIX}.
EOF
      ;;
    3)
      cat <<EOF
${BOLD}Summary — Lab 3 (Troubleshoot VLAN 10/20)${NC}
- Verify 'vlan10'/'vlan20' exist on ${BASE_IF}, VLAN IDs (10/20), and IPs match the role.
- Confirm NM managing and link is up.
EOF
      ;;
    4)
      cat <<EOF
${BOLD}Summary — Lab 4 (Configure Trunk on ${BASE_IF}: VLAN 50 & 60)${NC}
- Ensure both 'vlan50' and 'vlan60' exist and are active on ${BASE_IF}.
- Optional peer pings on vlan50/vlan60 to demonstrate reachability.
EOF
      ;;
    5)
      cat <<EOF
${BOLD}Summary — Lab 5 (Configure Access on ${BASE_IF})${NC}
- Switch Netplan to NetworkManager; ensure NM manages devices.
- Configure an UNTAGGED access connection on ${BASE_IF} with role-based IPv4.
- Optional peer ping on untagged to demonstrate reachability.
EOF
      ;;
    6)
      cat <<EOF
${BOLD}Summary — Lab 6 (Troubleshoot Trunk/Access)${NC}
- Detect mode and validate interfaces/IPs; optional peer pings with hints.
EOF
      ;;
    *)
      echo -e "${FAIL} Unknown lab $lab"
      ;;
  esac
}

# =========================
# APPLY FUNCTIONS (hardcoded ens4)
# =========================
lab1_apply(){
  nm_require_and_ensure_renderer
  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$V10_S1_IP"; [[ "$role" == "2" ]] && ip="$V10_S2_IP"

  q nmcli con delete "${NM_CONN_V10}"
  nmcli con add type vlan ifname vlan10 con-name "${NM_CONN_V10}" dev "${BASE_IF}" id 10 \
    ipv4.addresses "${ip}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null
  q nmcli con up "${NM_CONN_V10}"
}
lab2_apply(){
  nm_require_and_ensure_renderer
  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$V20_S1_IP"; [[ "$role" == "2" ]] && ip="$V20_S2_IP"

  q nmcli con delete "${NM_CONN_V20}"
  nmcli con add type vlan ifname vlan20 con-name "${NM_CONN_V20}" dev "${BASE_IF}" id 20 \
    ipv4.addresses "${ip}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null
  q nmcli con up "${NM_CONN_V20}"
}
lab3_apply(){ nm_require_and_ensure_renderer; }
lab4_apply(){  # NEW: trunk of VLAN 50 & VLAN 60
  nm_require_and_ensure_renderer
  local role ip50 ip60
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip50="$V50_S1_IP"; [[ "$role" == "2" ]] && ip50="$V50_S2_IP"
  ip60="$V60_S1_IP"; [[ "$role" == "2" ]] && ip60="$V60_S2_IP"

  q nmcli con delete "${NM_CONN_V50}"
  q nmcli con delete "${NM_CONN_V60}"

  nmcli con add type vlan ifname vlan50 con-name "${NM_CONN_V50}" dev "${BASE_IF}" id 50 \
    ipv4.addresses "${ip50}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null
  nmcli con add type vlan ifname vlan60 con-name "${NM_CONN_V60}" dev "${BASE_IF}" id 60 \
    ipv4.addresses "${ip60}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null

  q nmcli con up "${NM_CONN_V50}"
  q nmcli con up "${NM_CONN_V60}"
}
lab5_apply(){
  nm_require_and_ensure_renderer
  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$ACC_S1_IP"; [[ "$role" == "2" ]] && ip="$ACC_S2_IP"

  q nmcli con delete "${NM_CONN_ACC}"
  nmcli con add type ethernet ifname "${BASE_IF}" con-name "${NM_CONN_ACC}" \
    ipv4.addresses "${ip}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null
  q nmcli con down "${NM_CONN_V10}"; q nmcli con down "${NM_CONN_V20}"
  q nmcli con down "${NM_CONN_V50}"; q nmcli con down "${NM_CONN_V60}"
  q nmcli con up "${NM_CONN_ACC}"
}

# =========================
# CHECK FUNCTIONS (hardcoded ens4 + robust VLAN ID)
# =========================
lab1_check(){
  begin_check
  nm_is_active && good "NetworkManager is active" || miss "NetworkManager is not active"
  nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V10}" && \
    good "Connection '${NM_CONN_V10}' exists" || miss "Connection '${NM_CONN_V10}' missing"

  ip link show vlan10 >/dev/null 2>&1 && good "vlan10 interface present" || miss "vlan10 missing"

  check_vlan_id "vlan10" "10" "${NM_CONN_V10}" && good "vlan10 id 10 OK" || miss "vlan10 id mismatch"

  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$V10_S1_IP"; [[ "$role" == "2" ]] && ip="$V10_S2_IP"
  ip -4 -o addr show dev vlan10 2>/dev/null | grep -q " ${ip}/" && \
    good "vlan10 has ${ip}/${PREFIX}" || miss "vlan10 missing ${ip}/${PREFIX}"
  end_check
}
lab2_check(){
  begin_check
  nm_is_active && good "NetworkManager is active" || miss "NetworkManager is not active"
  nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V20}" && \
    good "Connection '${NM_CONN_V20}' exists" || miss "Connection '${NM_CONN_V20}' missing"

  ip link show vlan20 >/dev/null 2>&1 && good "vlan20 interface present" || miss "vlan20 missing"

  check_vlan_id "vlan20" "20" "${NM_CONN_V20}" && good "vlan20 id 20 OK" || miss "vlan20 id mismatch"

  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$V20_S1_IP"; [[ "$role" == "2" ]] && ip="$V20_S2_IP"
  ip -4 -o addr show dev vlan20 2>/dev/null | grep -q " ${ip}/" && \
    good "vlan20 has ${ip}/${PREFIX}" || miss "vlan20 missing ${ip}/${PREFIX}"
  end_check
}
lab3_check(){
  begin_check
  nm_is_active && good "NetworkManager is active" || miss "NetworkManager is not active"

  local role ip10 ip20
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip10="$V10_S1_IP"; [[ "$role" == "2" ]] && ip10="$V10_S2_IP"
  ip20="$V20_S1_IP"; [[ "$role" == "2" ]] && ip20="$V20_S2_IP"

  nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V10}" && good "'${NM_CONN_V10}' exists" || miss "'${NM_CONN_V10}' missing"
  ip link show vlan10 >/dev/null 2>&1 && good "vlan10 present" || miss "vlan10 missing"
  check_vlan_id "vlan10" "10" "${NM_CONN_V10}" && good "vlan10 id 10 OK" || miss "vlan10 id mismatch"
  ip -4 -o addr show dev vlan10 | grep -q " ${ip10}/" && good "vlan10 has ${ip10}/${PREFIX}" || miss "vlan10 missing ${ip10}/${PREFIX}"

  nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V20}" && good "'${NM_CONN_V20}' exists" || miss "'${NM_CONN_V20}' missing"
  ip link show vlan20 >/dev/null 2>&1 && good "vlan20 present" || miss "vlan20 missing"
  check_vlan_id "vlan20" "20" "${NM_CONN_V20}" && good "vlan20 id 20 OK" || miss "vlan20 id mismatch"
  ip -4 -o addr show dev vlan20 | grep -q " ${ip20}/" && good "vlan20 has ${ip20}/${PREFIX}" || miss "vlan20 missing ${ip20}/${PREFIX}"
  end_check
}
lab4_check(){  # UPDATED: check VLAN 50 & 60 trunk
  begin_check
  local role ip50 ip60 peer50 peer60
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip50="$V50_S1_IP"; [[ "$role" == "2" ]] && ip50="$V50_S2_IP"
  ip60="$V60_S1_IP"; [[ "$role" == "2" ]] && ip60="$V60_S2_IP"
  peer50="$(peer_ip "$role" "$V50_S1_IP" "$V50_S2_IP")"
  peer60="$(peer_ip "$role" "$V60_S1_IP" "$V60_S2_IP")"

  if nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V50}" && \
     nmcli -t -f NAME connection show | grep -qx "${NM_CONN_V60}"; then
    good "Both VLAN connections (50 & 60) exist"
  else
    miss "Trunk incomplete: one or both VLAN (50/60) connections missing"
  fi

  ip link show vlan50 >/dev/null 2>&1 && good "vlan50 present" || miss "vlan50 missing"
  check_vlan_id "vlan50" "50" "${NM_CONN_V50}" && good "vlan50 id 50 OK" || miss "vlan50 id mismatch"
  ip -4 -o addr show dev vlan50 | grep -q " ${ip50}/" && good "vlan50 has ${ip50}/${PREFIX}" || miss "vlan50 missing ${ip50}/${PREFIX}"

  ip link show vlan60 >/dev/null 2>&1 && good "vlan60 present" || miss "vlan60 missing"
  check_vlan_id "vlan60" "60" "${NM_CONN_V60}" && good "vlan60 id 60 OK" || miss "vlan60 id mismatch"
  ip -4 -o addr show dev vlan60 | grep -q " ${ip60}/" && good "vlan60 has ${ip60}/${PREFIX}" || miss "vlan60 missing ${ip60}/${PREFIX}"

  ping_on_iface "vlan50" "$peer50" "TRUNK-vlan50"
  ping_on_iface "vlan60" "$peer60" "TRUNK-vlan60"
  end_check
}
lab5_check(){
  begin_check
  local role ip peer
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$ACC_S1_IP"; [[ "$role" == "2" ]] && ip="$ACC_S2_IP"
  peer="$(peer_ip "$role" "$ACC_S1_IP" "$ACC_S2_IP")"

  nmcli -t -f NAME connection show | grep -qx "${NM_CONN_ACC}" && \
    good "Access connection '${NM_CONN_ACC}' exists" || miss "Access connection '${NM_CONN_ACC}' missing"

  ip -4 -o addr show dev "${BASE_IF}" 2>/dev/null | grep -q " ${ip}/" && \
    good "Base ${BASE_IF} has ${ip}/${PREFIX}" || miss "Base ${BASE_IF} lacks ${ip}/${PREFIX}"

  ping_on_iface "${BASE_IF}" "$peer" "ACCESS-untagged"

  if ip link show vlan10 >/dev/null 2>&1 || ip link show vlan20 >/dev/null 2>&1 \
     || ip link show vlan50 >/dev/null 2>&1 || ip link show vlan60 >/dev/null 2>&1; then
    echo -e "${WARN} VLAN subinterfaces present in access mode; ensure peer matches."
  fi
  end_check
}
lab6_check(){
  begin_check
  local active_conns mode=""
  active_conns="$(nmcli -t -f NAME connection show --active 2>/dev/null || true)"
  if echo "$active_conns" | grep -qx "${NM_CONN_ACC}"; then
    mode="access"
  elif echo "$active_conns" | grep -qE "^(${NM_CONN_V10}|${NM_CONN_V20}|${NM_CONN_V50}|${NM_CONN_V60})$"; then
    mode="trunk"
  else
    mode="unknown"
  fi
  [[ "$mode" == "access" ]] && good "Detected ACCESS mode"
  [[ "$mode" == "trunk"  ]] && good "Detected TRUNK mode"
  [[ "$mode" == "unknown" ]] && miss "Unable to detect mode (no expected active connections)"

  local role accip peeracc
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  accip="$ACC_S1_IP"; [[ "$role" == "2" ]] && accip="$ACC_S2_IP"
  peeracc="$(peer_ip "$role" "$ACC_S1_IP" "$ACC_S2_IP")"

  if [[ "$mode" == "trunk" ]]; then
    # Validate any present trunk VLANs (10/20/50/60)
    for spec in "vlan10 10 ${NM_CONN_V10} ${V10_S1_IP} ${V10_S2_IP}" \
                "vlan20 20 ${NM_CONN_V20} ${V20_S1_IP} ${V20_S2_IP}" \
                "vlan50 50 ${NM_CONN_V50} ${V50_S1_IP} ${V50_S2_IP}" \
                "vlan60 60 ${NM_CONN_V60} ${V60_S1_IP} ${V60_S2_IP}"; do
      set -- $spec
      local ifn="$1" vid="$2" conn="$3" ip_s1="$4" ip_s2="$5" ip_now peer_now
      ip_now="$ip_s1"; [[ "$role" == "2" ]] && ip_now="$ip_s2"
      peer_now="$(peer_ip "$role" "$ip_s1" "$ip_s2")"
      if ip link show "$ifn" >/dev/null 2>&1; then
        good "${ifn} present"
        check_vlan_id "$ifn" "$vid" "$conn" && good "${ifn} id $vid OK" || miss "${ifn} id mismatch"
        ip -4 -o addr show dev "$ifn" | grep -q " ${ip_now}/" && good "${ifn} has ${ip_now}/${PREFIX}" || miss "${ifn} missing ${ip_now}/${PREFIX}"
        ping_on_iface "$ifn" "$peer_now" "TRUNK-${ifn}"
      fi
    done
    # Mixed-mode hint
    ip -4 -o addr show dev "${BASE_IF}" 2>/dev/null | grep -q " ${accip}/" && \
      echo -e "${WARN} Base ${BASE_IF} has untagged ${accip}/${PREFIX} while in trunk (peer may be access)."
  elif [[ "$mode" == "access" ]]; then
    ip -4 -o addr show dev "${BASE_IF}" 2>/dev/null | grep -q " ${accip}/" && \
      good "Base ${BASE_IF} has ${accip}/${PREFIX}" || miss "Base ${BASE_IF} lacks ${accip}/${PREFIX}"
    ping_on_iface "${BASE_IF}" "$peeracc" "ACCESS-untagged"
    if ip link show vlan10 >/dev/null 2>&1 || ip link show vlan20 >/dev/null 2>&1 \
       || ip link show vlan50 >/dev/null 2>&1 || ip link show vlan60 >/dev/null 2>&1; then
      echo -e "${WARN} VLANs present in access mode; ensure peer matches."
    fi
  fi
  end_check
}

# =========================
# APPLY (with summaries)
# =========================
apply_lab(){
  local lab="$1" role="$2"
  save_state role "$role"
  summary_for_lab "$lab"
  case "$lab" in
    1) lab1_apply ;;
    2) lab2_apply ;;
    3) lab3_apply ;;
    4) lab4_apply ;;     # UPDATED trunk
    5) lab5_apply ;;
    6) nm_require_and_ensure_renderer ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
  save_state lab "$lab"
  echo -e "${OK} Applied Lab ${lab}"
}
do_check(){
  local lab="$1"
  case "$lab" in
    1) lab1_check ;;
    2) lab2_check ;;
    3) lab3_check ;;
    4) lab4_check ;;     # UPDATED trunk
    5) lab5_check ;;
    6) lab6_check ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# =========================
# RESET / STATUS / LIST
# =========================
reset_all(){
  nm_is_active || q systemctl enable --now NetworkManager
  q nmcli con delete "${NM_CONN_V10}"
  q nmcli con delete "${NM_CONN_V20}"
  q nmcli con delete "${NM_CONN_V50}"   # NEW
  q nmcli con delete "${NM_CONN_V60}"   # NEW
  q nmcli con delete "${NM_CONN_ACC}"
  : > "${STATE_FILE}" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}
status(){
  local lab
  lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Links:"; ip -o link show | awk -F': ' '{print " - " $2}'
  echo -e "${INFO} Base IF: ${BASE_IF}"
  ip -4 -o addr show dev "${BASE_IF}" || true
  if command -v nmcli >/dev/null 2>&1; then
    echo -e "${INFO} NM devices:"; nmcli -t -f DEVICE,STATE,CONNECTION device status || true
    echo -e "${INFO} NM active connections:"; nmcli -t -f NAME,DEVICE connection show --active || true
  fi
}
print_list(){
  cat <<EOF
${BOLD}Section 3 Labs${NC}
1. Creating VLAN Interfaces (CONFIG): vlan10 + static IP (on ens4)
2. Creating VLAN Interfaces (CONFIG): vlan20 + static IP (on ens4)
3. Creating VLAN Interfaces (TROUBLESHOOT)
4. Trunk Ports (CONFIG): vlan50 + vlan60 active (+ optional peer pings)   <-- UPDATED
5. Access Ports (CONFIG): untagged on ens4 (+ optional peer ping)
6. Trunk/Access (TROUBLESHOOT)

Usage:
  sudo $0 <lab#> apply <role>
  sudo $0 <lab#> check
  sudo $0 reset
  sudo $0 status
  sudo $0 list
  sudo $0 solutions <lab#>
  sudo $0 tips <lab#>

Optional:
  S3_PING=0   # disable peer pings (default 1)
  S3_PING_COUNT=2 S3_PING_TIMEOUT=1  # tune ping params
EOF
}

# =========================
# SOLUTIONS (with extended nmcli "Verify" blocks)
# =========================
print_solution(){
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1)
      cat <<'EOS'
Goal: Create VLAN 10 on ens4 with static IP (role-based)
1) Switch Netplan to NetworkManager (renderer), ensure NM manages devices.
2) Create VLAN 10 via NetworkManager:
   nmcli con delete s3-vlan10
   nmcli con add type vlan ifname vlan10 con-name s3-vlan10 dev ens4 id 10 \
     ipv4.addresses <ROLE_IP>/24 ipv4.method manual ipv6.method ignore
   nmcli con up s3-vlan10
3) Verify (interfaces & profile):
   ip -d link show vlan10 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+10)|(^|[[:space:]])id[[:space:]]+10([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan10
   ip -4 addr show dev vlan10
4) Verify (nmcli snapshot, similar style):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active | grep s3-vlan10 || true
   nmcli con show s3-vlan10 | grep 802-3-ethernet.mtu || true
   nmcli con show s3-vlan10 | grep ipv4
   nmcli -g ip4 connection show s3-vlan10
EOS
      ;;
    2)
      cat <<'EOS'
Goal: Create VLAN 20 on ens4 with static IP (role-based)
1) Switch Netplan to NetworkManager (renderer), ensure NM manages devices.
2) Create VLAN 20:
   nmcli con delete s3-vlan20
   nmcli con add type vlan ifname vlan20 con-name s3-vlan20 dev ens4 id 20 \
     ipv4.addresses <ROLE_IP>/24 ipv4.method manual ipv6.method ignore
   nmcli con up s3-vlan20
3) Verify (interfaces & profile):
   ip -d link show vlan20 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+20)|(^|[[:space:]])id[[:space:]]+20([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan20
   ip -4 addr show dev vlan20
4) Verify (nmcli snapshot):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active | grep s3-vlan20 || true
   nmcli con show s3-vlan20 | grep 802-3-ethernet.mtu || true
   nmcli con show s3-vlan20 | grep ipv4
   nmcli -g ip4 connection show s3-vlan20
EOS
      ;;
    3)
      cat <<'EOS'
Goal: Troubleshoot VLAN Interfaces (vlan10/vlan20 on ens4)
1) Confirm NM & renderer:
   systemctl is-active NetworkManager
   grep -R "renderer: *NetworkManager" /etc/netplan/*.yaml
2) Confirm connections:
   nmcli -t -f NAME connection show | grep -x s3-vlan10
   nmcli -t -f NAME connection show | grep -x s3-vlan20
3) Validate VLAN IDs:
   ip -d link show vlan10 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+10)|(^|[[:space:]])id[[:space:]]+10([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan10
   ip -d link show vlan20 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+20)|(^|[[:space:]])id[[:space:]]+20([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan20
4) Validate addressing:
   ip -4 -o addr show dev vlan10
   ip -4 -o addr show dev vlan20
5) Extended Verify (nmcli snapshot):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active
   nmcli con show s3-vlan10 | egrep "802-3-ethernet.mtu|ipv4"
   nmcli -g ip4 connection show s3-vlan10
   nmcli con show s3-vlan20 | egrep "802-3-ethernet.mtu|ipv4"
   nmcli -g ip4 connection show s3-vlan20
EOS
      ;;
    4)
      cat <<'EOS'
Goal: Configure a Trunk (VLAN 50 & 60 on ens4)
1) Create VLAN 50 & 60:
   nmcli con delete s3-vlan50; nmcli con delete s3-vlan60
   nmcli con add type vlan ifname vlan50 con-name s3-vlan50 dev ens4 id 50 \
     ipv4.addresses <ROLE_IP_50>/24 ipv4.method manual ipv6.method ignore
   nmcli con add type vlan ifname vlan60 con-name s3-vlan60 dev ens4 id 60 \
     ipv4.addresses <ROLE_IP_60>/24 ipv4.method manual ipv6.method ignore
   nmcli con up s3-vlan50
   nmcli con up s3-vlan60
2) Verify (interfaces & profile):
   ip -d link show vlan50 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+50)|(^|[[:space:]])id[[:space:]]+50([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan50
   ip -4 addr show dev vlan50
   ip -d link show vlan60 | grep -Ei "(vlan[[:space:]]+id[[:space:]]+60)|(^|[[:space:]])id[[:space:]]+60([[:space:]]|$)"
   nmcli -g vlan.id connection show s3-vlan60
   ip -4 addr show dev vlan60
3) Extended Verify (nmcli snapshot, similar style):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active | egrep "s3-vlan50|s3-vlan60" || true
   nmcli con show s3-vlan50 | egrep "802-3-ethernet.mtu|ipv4" || true
   nmcli -g ip4 connection show s3-vlan50
   nmcli con show s3-vlan60 | egrep "802-3-ethernet.mtu|ipv4" || true
   nmcli -g ip4 connection show s3-vlan60
4) Optional: ping peer server on each VLAN:
   ping -I vlan50 <peer-ip-vlan50>
   ping -I vlan60 <peer-ip-vlan60>
EOS
      ;;
    5)
      cat <<'EOS'
Goal: Configure Access (untagged) on ens4
1) Create untagged connection:
   nmcli con delete s3-access
   nmcli con add type ethernet ifname ens4 con-name s3-access \
     ipv4.addresses <ROLE_IP>/24 ipv4.method manual ipv6.method ignore
   nmcli con up s3-access
2) Optionally down VLAN connections:
   nmcli con down s3-vlan10; nmcli con down s3-vlan20
   nmcli con down s3-vlan50; nmcli con down s3-vlan60
3) Verify (interfaces & profile):
   ip -4 addr show dev ens4
4) Extended Verify (nmcli snapshot):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active | grep s3-access || true
   nmcli con show s3-access | egrep "802-3-ethernet.mtu|ipv4"
   nmcli -g ip4 connection show s3-access
EOS
      ;;
    6)
      cat <<'EOS'
Goal: Troubleshoot Trunk vs Access
1) Detect mode:
   nmcli -t -f NAME connection show --active
   # 's3-access' active -> ACCESS; any of s3-vlan10/20/50/60 active -> TRUNK
2) Validate per mode:
   TRUNK: target VLAN(s) present, correct IDs (ip -d + nmcli vlan.id), correct IPs, optional pings
   ACCESS: base ens4 has untagged role IP, optional ping
3) Extended Verify (nmcli snapshot):
   nmcli dev status
   nmcli general status
   nmcli -t -f NAME,DEVICE connection show --active
   nmcli con show s3-access | egrep "802-3-ethernet.mtu|ipv4" || true
   nmcli -g ip4 connection show s3-access || true
   nmcli con show s3-vlan50 | egrep "802-3-ethernet.mtu|ipv4" || true
   nmcli -g ip4 connection show s3-vlan50 || true
   nmcli con show s3-vlan60 | egrep "802-3-ethernet.mtu|ipv4" || true
   nmcli -g ip4 connection show s3-vlan60 || true
4) Common issues:
   - Mode mismatch between servers
   - Duplicate IPs (ARP conflicts)
   - Wrong VLAN IDs
   - Carrier down
EOS
      ;;
    *)
      echo -e "${FAIL} Unknown lab $lab"
      ;;
  esac
  echo "----------------------------------------"
}

# =========================
# TIPS
# =========================
print_tip(){
  local lab="$1"
  echo -e "${BOLD}Tips for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab$" in
    1) echo "If 'device is unmanaged', ensure Netplan renderer is NetworkManager and NM conf.d overrides are present." ;;
    2) echo "VLAN ID must match on both ends; verify with ip -d AND nmcli -g vlan.id." ;;
    3) echo "For 'IP not reserved', check ARP conflicts (arping -D -I ens4 <ip>) and NM logs." ;;
    4) echo "Trunk now uses VLAN 50 & 60; ping peers per VLAN to validate reachability end-to-end." ;;
    5) echo "Access = untagged; both ends must use access or frames won't match." ;;
    6) echo "If pings fail: check mode symmetry, subnet, link/carrier, and duplicates." ;;
    *) echo -e "${FAIL} Unknown lab $lab" ;;
  esac
  echo "----------------------------------------"
}

# =========================
# INTERACTIVE MENU / MAIN
# =========================
interactive_menu(){
  while true; do
    clear
    echo -e "${BOLD}Section 3 Labs Menu${NC}"
    echo "1) Apply Lab"
    echo "2) Check Lab"
    echo "3) Reset"
    echo "4) Status"
    echo "5) List Labs"
    echo "6) Solutions"
    echo "7) Tips"
    echo "q) Quit"
    read -rp "Select option: " opt
    case "$opt" in
      1) read -rp "Lab (1-6): " lab; read -rp "Server role (1 or 2): " role; summary_for_lab "$lab"; apply_lab "$lab" "$role"; read -rp "Press Enter..." ;;
      2) read -rp "Lab (1-6): " lab; do_check "$lab"; read -rp "Press Enter..." ;;
      3) reset_all; read -rp "Press Enter..." ;;
      4) status; read -rp "Press Enter..." ;;
      5) print_list; read -rp "Press Enter..." ;;
      6) read -rp "Lab (1-6): " lab; clear; print_solution "$lab"; read -rp "Press Enter..." ;;
      7) read -rp "Lab (1-6): " lab; clear; print_tip "$lab"; read -rp "Press Enter..." ;;
      q|Q) exit 0 ;;
      *) echo "Invalid selection"; sleep 1 ;;
    esac
  done
}

main(){
  mkdirs
  if [[ $# -lt 1 ]]; then interactive_menu; exit 0; fi
  case "$1" in
    list) print_list; exit 0 ;;
    status) status; exit 0 ;;
    reset) reset_all; exit 0 ;;
    solutions) [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }; print_solution "$2"; exit 0 ;;
    tips) [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 tips <lab#>"; exit 2; }; print_tip "$2"; exit 0 ;;
  esac
  local lab="$1"
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 <lab#> apply|check [role]"; exit 2; }
  case "$2" in
    apply) [[ $# -lt 3 ]] && { echo -e "${FAIL} Missing role. Use: 1 or 2"; exit 2; }; summary_for_lab "$lab"; apply_lab "$lab" "$3" ;;
    check) do_check "$lab" ;;
    *) echo -e "${FAIL} Use: apply | check"; exit 2 ;;
  esac
}
main "$@"
