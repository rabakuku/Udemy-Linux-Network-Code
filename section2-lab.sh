#!/usr/bin/env bash
# Section 2 - Regular Labs (Persistent Configs, No Runtime Hacks)
# Labs:
# 1) Naming (CONFIG): netplan set-name -> lan0 + static IP
# 2) Naming (CONFIG): netplan set-name -> wan0 + static IP
# 3) VLAN (CONFIG): netplan VLAN 'vlan10' on primary NIC + static IP
# 4) NetworkManager (CONFIG): switch renderer to NM + static profile via nmcli
# 5) NetworkManager (CONFIG): change MTU via NM (802-3-ethernet.mtu=1400)
# 6) NetworkManager (CONFIG): set IPv4 DNS on connection via NM (1.1.1.1, 8.8.8.8)
# 7) Loopback (CONFIG): persistent 127.0.0.2/8, 127.0.0.3/8 via systemd-networkd
# Menu: Apply / Check / Reset / Status / List / Solutions / Tips

if [[ -n "${LABS_DEBUG:-}" ]]; then set -x; fi
set -Eeuo pipefail
trap 'echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2' ERR

# ===== User variables =====
S1_IP="10.10.20.11"
S2_IP="10.10.20.12"
PREFIX="24"
VLAN10_IP="10.10.20.21"
NM_DNS1="1.1.1.1"
NM_DNS2="8.8.8.8"

# ===== Paths / State =====
LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"
NETPLAN_DIR="/etc/netplan"
NETPLAN_BACKUP_DIR="${LAB_ROOT}/netplan-backups"
NETPLAN_STASH="${LAB_ROOT}/netplan-stash"
NM_NETPLAN_FILE="${NETPLAN_DIR}/10-section2-nm.yaml"
NETD_DIR="/etc/systemd/network"
NETD_BACKUP_DIR="${LAB_ROOT}/netd-backups"
LO_NET_FILE="${NETD_DIR}/10-section2-lo.network"
NM_CONF_DIR="/etc/NetworkManager/conf.d"
NM_CONN_NAME="labs-primary"

# ===== Colors / icons =====
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"; WARN="${YELLOW}[!]${NC}"

# ===== Helpers =====
q() { "$@" >/dev/null 2>&1 || true; }
mkdirs() { mkdir -p "$LAB_ROOT" "$NETPLAN_BACKUP_DIR" "$NETD_BACKUP_DIR"; }
save_state() {
  local k="$1" v="$2"
  mkdirs; touch "$STATE_FILE"
  if grep -q "^${k}=" "$STATE_FILE" 2>/dev/null; then
    sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE"
  else
    echo "${k}=${v}" >>"$STATE_FILE"
  fi
}
get_state() {
  local k="$1"
  [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
  grep "^${k}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true
}
need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${WARN} Please run as root: sudo $0 $*"
    exit 1
  fi
}
primary_if() {
  if ip link show ens4 >/dev/null 2>&1; then echo "ens4"; return 0; fi
  if ip link show lan0 >/dev/null 2>&1; then echo "lan0"; return 0; fi
  ip -o link show | awk -F': ' '{print $2}' \
    | grep -E '^(en|eth|eno|ens|enp|lan)[a-z0-9]+' \
    | grep -v '^lo$' | head -n1
}
iface_mac() { local ifc="$1"; cat "/sys/class/net/${ifc}/address" 2>/dev/null || echo ""; }
nm_is_active() { command -v nmcli >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager; }
write_file() { # write_file <path> <mode> (reads content from stdin)
  local path="$1" mode="$2"
  umask 022
  cat >"$path"
  chmod "$mode" "$path" || true
  chown root:root "$path" || true
}
backup_netplan_once() {
  mkdirs
  if [[ ! -f "${NETPLAN_BACKUP_DIR}/bundle-INITIAL.tgz" && -d "$NETPLAN_DIR" ]]; then
    tar -C "$NETPLAN_DIR" -czf "${NETPLAN_BACKUP_DIR}/bundle-INITIAL.tgz" . 2>/dev/null || true
    echo -e "${INFO} Backed up netplan to ${NETPLAN_BACKUP_DIR}/bundle-INITIAL.tgz"
  fi
}
backup_netd_once() {
  mkdirs
  if [[ ! -f "${NETD_BACKUP_DIR}/bundle-INITIAL.tgz" && -d "$NETD_DIR" ]]; then
    tar -C "$NETD_DIR" -czf "${NETD_BACKUP_DIR}/bundle-INITIAL.tgz" . 2>/dev/null || true
    echo -e "${INFO} Backed up systemd-networkd to ${NETD_BACKUP_DIR}/bundle-INITIAL.tgz"
  fi
}
restore_netplan() {
  if [[ -d "$NETPLAN_STASH" ]]; then
    shopt -s nullglob
    for f in "$NETPLAN_STASH"/*.yaml; do mv -f "$f" "$NETPLAN_DIR"/; done
    rmdir "$NETPLAN_STASH" 2>/dev/null || true
  elif [[ -f "${NETPLAN_BACKUP_DIR}/bundle-INITIAL.tgz" ]]; then
    shopt -s nullglob
    for f in "$NETPLAN_DIR"/*.yaml; do rm -f "$f"; done
    tar -C "$NETPLAN_DIR" -xzf "${NETPLAN_BACKUP_DIR}/bundle-INITIAL.tgz" 2>/dev/null || true
  fi
  q netplan generate
  q netplan apply
}
stash_all_netplan() {
  mkdir -p "$NETPLAN_STASH"
  shopt -s nullglob
  for f in "$NETPLAN_DIR"/*.yaml; do
    [[ -f "$NETPLAN_STASH/$(basename "$f")" ]] && continue
    mv -f "$f" "$NETPLAN_STASH"/
  done
}

# ===== Check reporting helpers =====
begin_check() { FAILS=0; }
good() { echo -e "${OK} $*"; }
miss() { echo -e "${FAIL} $*"; FAILS=$((FAILS+1)); }
end_check() {
  if [[ ${FAILS:-0} -eq 0 ]]; then
    echo -e "${OK} All checks passed"
  else
    echo -e "${FAIL} ${FAILS} issue(s) found"
    exit 4
  fi
}

# ===== Summaries =====
summary_for_lab() {
  local lab="$1"
  case "$lab" in
    1)
      cat <<EOF
${BOLD}Summary — Lab 1 (Netplan: name -> lan0 + static IP)${NC}
- Detect primary NIC and its MAC.
- Create netplan YAML with 'set-name: lan0' matched by MAC.
- Assign IPv4 ${S1_IP}/${PREFIX} (role 1) or ${S2_IP}/${PREFIX} (role 2).
- Apply with: netplan generate && netplan apply.
EOF
      ;;
    2)
      cat <<EOF
${BOLD}Summary — Lab 2 (Netplan: name -> wan0 + static IP)${NC}
- Detect primary NIC and its MAC.
- Create netplan YAML with 'set-name: wan0' matched by MAC.
- Assign IPv4 ${S1_IP}/${PREFIX} (role 1) or ${S2_IP}/${PREFIX} (role 2).
- Apply with: netplan generate && netplan apply.
EOF
      ;;
    3)
      cat <<EOF
${BOLD}Summary — Lab 3 (Netplan: VLAN 10 'vlan10' + static IP)${NC}
- Detect primary NIC (as VLAN lower-device).
- Define 'vlan10' with id: 10 and link: <primary>.
- Assign IPv4 ${VLAN10_IP}/${PREFIX}.
- Apply with: netplan generate && netplan apply.
EOF
      ;;
    4)
      cat <<EOF
${BOLD}Summary — Lab 4 (Switch to NetworkManager + static profile)${NC}
- Stash any existing netplan files; write NM renderer YAML.
- Ensure NetworkManager service is enabled and active.
- Create 'labs-primary' ethernet connection on primary NIC.
- Set IPv4 ${S1_IP}/${PREFIX} (role 1) or ${S2_IP}/${PREFIX} (role 2), IPv6 ignored.
EOF
      ;;
    5)
      cat <<EOF
${BOLD}Summary — Lab 5 (NM: set MTU 1400 on 'labs-primary')${NC}
- Modify 'labs-primary' connection: 802-3-ethernet.mtu=1400.
- Reactivate the connection to apply MTU.
EOF
      ;;
    6)
      cat <<EOF
${BOLD}Summary — Lab 6 (NM: set IPv4 DNS on 'labs-primary')${NC}
- Set IPv4 DNS servers to ${NM_DNS1}, ${NM_DNS2}.
- Enable 'ipv4.ignore-auto-dns yes' to prefer manual DNS.
- Reactivate the connection.
EOF
      ;;
    7)
      cat <<EOF
${BOLD}Summary — Lab 7 (networkd: add loopback IPs)${NC}
- Create /etc/systemd/network/10-section2-lo.network for 'lo'.
- Add addresses 127.0.0.2/8 and 127.0.0.3/8.
- Enable & restart systemd-networkd.
EOF
      ;;
  esac
}

# =========================
# LAB APPLY FUNCTIONS
# =========================
# --- Interface Naming Labs ---
lab1_apply() {
  backup_netplan_once
  local ifc mac ip role
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ifc="$(primary_if)"; mac="$(iface_mac "$ifc")"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  [[ -z "$mac" ]] && { echo -e "${FAIL} Unable to read MAC for ${ifc}"; exit 2; }
  write_file "${NETPLAN_DIR}/10-section2-lab1.yaml" 0600 <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${ifc}:
      match:
        macaddress: ${mac}
      set-name: lan0
      addresses: [ ${ip}/${PREFIX} ]
EOF
  q netplan generate
  q netplan apply
}
lab2_apply() {
  backup_netplan_once
  local ifc mac ip role
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ifc="$(primary_if)"; mac="$(iface_mac "$ifc")"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  [[ -z "$mac" ]] && { echo -e "${FAIL} Unable to read MAC for ${ifc}"; exit 2; }
  write_file "${NETPLAN_DIR}/20-section2-lab2.yaml" 0600 <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${ifc}:
      match:
        macaddress: ${mac}
      set-name: wan0
      addresses: [ ${ip}/${PREFIX} ]
EOF
  q netplan generate
  q netplan apply
}

# --- VLAN (Configuration) ---
lab3_apply() {
  backup_netplan_once
  local ifc
  ifc="$(primary_if)"
  [[ -z "$ifc" ]] && { echo -e "${FAIL} No primary NIC detected"; exit 2; }
  write_file "${NETPLAN_DIR}/25-section2-lab3-vlan10.yaml" 0600 <<EOF
network:
  version: 2
  renderer: networkd
  vlans:
    vlan10:
      id: 10
      link: ${ifc}
      addresses: [ ${VLAN10_IP}/${PREFIX} ]
EOF
  q netplan generate
  q netplan apply
}

# --- NetworkManager Labs ---
ensure_nm_ready_or_fail() {
  if ! command -v nmcli >/dev/null 2>&1; then
    echo -e "${FAIL} NetworkManager (nmcli) not installed. Install: sudo apt-get install -y network-manager"
    exit 2
  fi
  q systemctl enable --now NetworkManager
  if ! systemctl is-active --quiet NetworkManager; then
    echo -e "${FAIL} NetworkManager is not active. Start it: sudo systemctl enable --now NetworkManager"
    exit 2
  fi
}
switch_netplan_to_nm_clean() {
  backup_netplan_once
  stash_all_netplan
  write_file "${NM_NETPLAN_FILE}" 0600 <<'EOF'
network:
  version: 2
  renderer: NetworkManager
EOF
  q netplan generate
  q netplan apply
}
nm_iface() { primary_if; }

lab4_apply() {
  ensure_nm_ready_or_fail
  switch_netplan_to_nm_clean
  local role ip ifc
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  ifc="$(nm_iface)"; [[ -z "$ifc" ]] && { echo -e "${FAIL} No suitable NIC for NM"; exit 2; }
  q nmcli con delete "${NM_CONN_NAME}"
  nmcli con add type ethernet ifname "${ifc}" con-name "${NM_CONN_NAME}" \
    ipv4.addresses "${ip}/${PREFIX}" ipv4.method manual ipv6.method ignore >/dev/null 2>&1 || true
  q nmcli device set "${ifc}" managed yes
  q nmcli con up "${NM_CONN_NAME}"
}

lab5_apply() {
  ensure_nm_ready_or_fail
  if ! nmcli -t -f NAME connection show | grep -qx "${NM_CONN_NAME}"; then
    echo -e "${FAIL} NM connection '${NM_CONN_NAME}' not found. Run Lab 4 first."
    exit 2
  fi
  q nmcli con modify "${NM_CONN_NAME}" 802-3-ethernet.mtu 1400
  q nmcli con up "${NM_CONN_NAME}"
}

lab6_apply() {
  ensure_nm_ready_or_fail
  if ! nmcli -t -f NAME connection show | grep -qx "${NM_CONN_NAME}"; then
    echo -e "${FAIL} NM connection '${NM_CONN_NAME}' not found. Run Lab 4 first."
    exit 2
  fi
  q nmcli con modify "${NM_CONN_NAME}" ipv4.dns "${NM_DNS1} ${NM_DNS2}" ipv4.ignore-auto-dns yes
  q nmcli con up "${NM_CONN_NAME}"
}

# --- Loopback (Configuration) ---
lab7_apply() {
  backup_netd_once
  mkdir -p "$NETD_DIR"
  write_file "${LO_NET_FILE}" 0644 <<'EOF'
[Match]
Name=lo
[Network]
Address=127.0.0.2/8
Address=127.0.0.3/8
EOF
  q systemctl enable --now systemd-networkd
  q systemctl restart systemd-networkd
}

# =========================
# DEVICE RESOLUTION (shared)
# =========================
nm_conn_device() {
  # Usage: nm_conn_device <connection_name>
  local name="$1" dev=""
  # Prefer active device mapping
  dev="$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | awk -F: -v n="$name" '$1==n{print $2;exit}')"
  # If not active, use the connection's interface-name property
  [[ -z "$dev" ]] && dev="$(nmcli -t -g connection.interface-name connection show "$name" 2>/dev/null || true)"
  # Fallback: primary_if
  [[ -z "$dev" ]] && dev="$(primary_if)"
  echo "$dev"
}

# =========================
# LAB CHECK FUNCTIONS
# =========================
lab1_check() {
  begin_check
  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  if ip link show lan0 >/dev/null 2>&1; then
    good "'lan0' interface present"
  else
    miss "'lan0' interface missing"
  fi
  if ip -4 -o addr show dev lan0 2>/dev/null | grep -q " ${ip}/"; then
    good "IPv4 ${ip}/${PREFIX} is configured on lan0"
  else
    miss "Expected IPv4 ${ip}/${PREFIX} on lan0 is missing"
  fi
  end_check
}

lab2_check() {
  begin_check
  local role ip
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  if ip link show wan0 >/dev/null 2>&1; then
    good "'wan0' interface present"
  else
    miss "'wan0' interface missing"
  fi
  if ip -4 -o addr show dev wan0 2>/dev/null | grep -q " ${ip}/"; then
    good "IPv4 ${ip}/${PREFIX} is configured on wan0"
  else
    miss "Expected IPv4 ${ip}/${PREFIX} on wan0 is missing"
  fi
  end_check
}

lab3_check() {
  begin_check
  if ip link show vlan10 >/dev/null 2>&1; then
    good "'vlan10' interface present"
    if ip -d link show vlan10 2>/dev/null | grep -q "vlan id 10"; then
      good "vlan10 has VLAN id 10"
    else
      miss "vlan10 does not report VLAN id 10"
    fi
  else
    miss "'vlan10' interface missing"
  fi
  if ip -4 -o addr show dev vlan10 2>/dev/null | grep -q " ${VLAN10_IP}/"; then
    good "IPv4 ${VLAN10_IP}/${PREFIX} is configured on vlan10"
  else
    miss "Expected IPv4 ${VLAN10_IP}/${PREFIX} on vlan10 is missing"
  fi
  end_check
}

lab4_check() {
  begin_check

  # 1) NM is active
  if nm_is_active; then
    good "NetworkManager is active"
  else
    miss "NetworkManager is not active"
  fi

  # 2) Connection exists
  if nmcli -t -f NAME connection show 2>/dev/null | grep -qx "${NM_CONN_NAME}"; then
    good "NM connection '${NM_CONN_NAME}' exists"
  else
    miss "NM connection '${NM_CONN_NAME}' is missing"
  fi

  # 3) Netplan renderer is NetworkManager
  if grep -Rqs "renderer:[[:space:]]*NetworkManager" "$NETPLAN_DIR"/*.yaml 2>/dev/null; then
    good "Netplan renderer is NetworkManager"
  else
    miss "Netplan renderer is not set to NetworkManager"
  fi

  # 4) Resolve device reliably and check exact IPv4 address
  local role ip dev
  role="$(get_state role)"; [[ -z "$role" ]] && role="1"
  ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  dev="$(nm_conn_device "${NM_CONN_NAME}")"

  if [[ -n "$dev" ]] && ip -4 -o addr show dev "$dev" 2>/dev/null | grep -q " ${ip}/"; then
    good "Device ${dev} has IPv4 ${ip}/${PREFIX}"
  else
    miss "Expected IPv4 ${ip}/${PREFIX} on device '${dev:-unknown}' is missing"
  fi

  # 5) Device is managed by NM
  if [[ -n "$dev" ]] && nmcli -t -f DEVICE,STATE device status 2>/dev/null | awk -F: -v d="$dev" '$1==d{print $2}' | grep -Eq '^(connected|disconnected)$'; then
    good "Device ${dev} is managed by NetworkManager"
  else
    miss "Device ${dev:-unknown} is not managed (or not found) by NetworkManager"
  fi

  # 6) IPv6 method ignore (as configured in lab4_apply)
  if nmcli -g ipv6.method connection show "${NM_CONN_NAME}" 2>/dev/null | grep -qi '^ignore$'; then
    good "ipv6.method is 'ignore' on '${NM_CONN_NAME}'"
  else
    miss "ipv6.method is not 'ignore' on '${NM_CONN_NAME}'"
  fi

  end_check
}

lab5_check() {
  begin_check
  local dev
  dev="$(nm_conn_device "${NM_CONN_NAME}")"
  if [[ -n "$dev" ]] && ip link show "$dev" 2>/dev/null | grep -q "mtu 1400"; then
    good "MTU 1400 set on ${dev}"
  else
    miss "MTU 1400 not set (or device not detected)"
  fi
  end_check
}

lab6_check() {
  begin_check
  if nmcli -t -f NAME connection show 2>/dev/null | grep -qx "${NM_CONN_NAME}"; then
    good "NM connection '${NM_CONN_NAME}' exists"
    local dns
    dns="$(nmcli -g ip4.dns connection show "${NM_CONN_NAME}" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
    if echo " $dns " | grep -q " ${NM_DNS1} " && echo " $dns " | grep -q " ${NM_DNS2} "; then
      good "IPv4 DNS includes ${NM_DNS1}, ${NM_DNS2}"
    else
      miss "IPv4 DNS does not include ${NM_DNS1}, ${NM_DNS2} (current: ${dns:-none})"
    fi
    if nmcli -g ipv4.ignore-auto-dns connection show "${NM_CONN_NAME}" 2>/dev/null | grep -qi '^yes$'; then
      good "ipv4.ignore-auto-dns is enabled"
    else
      miss "ipv4.ignore-auto-dns is not enabled"
    fi
  else
    miss "NM connection '${NM_CONN_NAME}' is missing"
  fi
  end_check
}

lab7_check() {
  begin_check
  if ip -4 addr show dev lo | grep -q "127.0.0.2"; then
    good "loopback has 127.0.0.2/8"
  else
    miss "127.0.0.2/8 not present on loopback"
  fi
  if ip -4 addr show dev lo | grep -q "127.0.0.3"; then
    good "loopback has 127.0.0.3/8"
  else
    miss "127.0.0.3/8 not present on loopback"
  fi
  end_check
}

# =========================
# APPLY (with summaries)
# =========================
apply_lab() {
  local lab="$1" role="$2"
  save_state role "$role"
  summary_for_lab "$lab"
  case "$lab" in
    1) lab1_apply ;;
    2) lab2_apply ;;
    3) lab3_apply ;;
    4) lab4_apply ;;
    5) lab5_apply ;;
    6) lab6_apply ;;
    7) lab7_apply ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
  save_state lab "$lab"
  echo -e "${OK} Applied Lab ${lab}"
}
do_check() {
  local lab="$1"
  case "$lab" in
    1) lab1_check ;;
    2) lab2_check ;;
    3) lab3_check ;;
    4) lab4_check ;;
    5) lab5_check ;;
    6) lab6_check ;;
    7) lab7_check ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# =========================
# RESET / STATUS / LIST
# =========================
reset_all() {
  if command -v nmcli >/dev/null 2>&1; then
    q nmcli con delete "${NM_CONN_NAME}"
  fi
  # Clean any unmanaged conf if it was ever created by earlier versions
  if [[ -f "${NM_CONF_DIR}/99-section2-unmanaged.conf" ]]; then
    rm -f "${NM_CONF_DIR}/99-section2-unmanaged.conf"
    q systemctl restart NetworkManager
  fi
  if [[ -f "${LO_NET_FILE}" ]]; then
    rm -f "${LO_NET_FILE}"
    q systemctl restart systemd-networkd
  fi
  restore_netplan
  : > "${STATE_FILE}" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}
status() {
  local lab
  lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Links:"; ip -o link show | awk -F': ' '{print " - " $2}'
  local ifc; ifc="$(primary_if)"; [[ -n "$ifc" ]] && {
    echo -e "${INFO} Primary: ${ifc}"; ip -4 -o addr show dev "${ifc}" || true;
  }
  if command -v nmcli >/dev/null 2>&1; then
    echo -e "${INFO} NM devices:"; nmcli -t -f DEVICE,STATE,CONNECTION device status || true
  fi
}
print_list() {
  cat <<EOF
${BOLD}Section 2 Labs${NC}
1. Naming (CONFIG): netplan set-name -> lan0
2. Naming (CONFIG): netplan set-name -> wan0
3. VLAN (CONFIG): netplan vlan10 on primary link + ${VLAN10_IP}/${PREFIX}
4. NetworkManager (CONFIG): switch to NM + static profile
5. NetworkManager (CONFIG): MTU 1400 via NM
6. NetworkManager (CONFIG): set IPv4 DNS via NM
7. Loopback (CONFIG): persistent 127.0.0.2/8, 127.0.0.3/8
Usage:
  sudo $0 <lab#> apply <role>
  sudo $0 <lab#> check
  sudo $0 reset
  sudo $0 status
  sudo $0 list
  sudo $0 solutions <lab#>
  sudo $0 tips <lab#>
EOF
}

# =========================
# SOLUTIONS (quoted heredocs)
# =========================
print_solution() {
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1) cat <<'EOS'
Goal: Netplan set-name -> lan0 with static IP.
1) Find primary NIC + MAC:
   ip -o link show
   ip link show ens4 # or your primary
   cat /sys/class/net/ens4/address
2) Create netplan:
   sudo tee /etc/netplan/10-section2-lab1.yaml >/dev/null <<'YAML'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens4:
      match:
        macaddress: AA:BB:CC:DD:EE:FF
      set-name: lan0
      addresses: [ 10.10.20.11/24 ]
YAML
3) Apply:
   sudo netplan generate && sudo netplan apply
4) Verify:
   ip link show lan0
   ip -4 addr show dev lan0
EOS
      ;;
    2) cat <<'EOS'
Goal: Netplan set-name -> wan0 with static IP.
1) Collect MAC of primary NIC.
2) Create netplan:
   sudo tee /etc/netplan/20-section2-lab2.yaml >/dev/null <<'YAML'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens4:
      match:
        macaddress: AA:BB:CC:DD:EE:FF
      set-name: wan0
      addresses: [ 10.10.20.11/24 ]
YAML
3) Apply:
   sudo netplan generate && sudo netplan apply
4) Verify:
   ip link show wan0
   ip -4 addr show dev wan0
EOS
      ;;
    3) cat <<'EOS'
Goal: Netplan VLAN 'vlan10' on primary NIC with static IP.
1) Identify primary NIC (e.g., ens4).
2) Create netplan:
   sudo tee /etc/netplan/25-section2-lab3-vlan10.yaml >/dev/null <<'YAML'
network:
  version: 2
  renderer: networkd
  vlans:
    vlan10:
      id: 10
      link: ens4
      addresses: [ 10.10.20.21/24 ]
YAML
3) Apply:
   sudo netplan generate && sudo netplan apply
4) Verify:
   ip -d link show vlan10 | grep 'vlan id 10'
   ip -4 addr show dev vlan10
EOS
      ;;
    4) cat <<'EOS'
Goal: Switch to NetworkManager and create a static NM profile.
1) Stash existing netplan YAMLs; keep only NM renderer:
   sudo mkdir -p /etc/labs-menu/netplan-stash
   sudo sh -c 'mv -f /etc/netplan/*.yaml /etc/labs-menu/netplan-stash/ 2>/dev/null || true'
   sudo tee /etc/netplan/10-section2-nm.yaml >/dev/null <<'YAML'
network:
  version: 2
  renderer: NetworkManager
YAML
   sudo netplan generate && sudo netplan apply
2) Ensure NM is active:
   sudo apt-get install -y network-manager
   sudo systemctl enable --now NetworkManager
3) Create connection:
   nmcli con delete labs-primary
   nmcli con add type ethernet ifname ens4 con-name labs-primary \
     ipv4.addresses 10.10.20.11/24 ipv4.method manual ipv6.method ignore
   nmcli con up labs-primary
4) Verify:
   nmcli dev status
   nmcli general status
   nmcli con show labs-primary | grep ipv4
   nmcli -t -f NAME,DEVICE connection show --active | grep '^labs-primary:'
   nmcli -t -f NAME connection show | grep -x labs-primary
   nmcli -t -f DEVICE,STATE,CONNECTION device status
EOS
      ;;
    5) cat <<'EOS'
Goal: Change MTU to 1400 via NM.
1) Ensure 'labs-primary' exists (see Lab 4).
2) Modify MTU:
   nmcli con modify labs-primary 802-3-ethernet.mtu 1400
   nmcli con up labs-primary
3) Verify:
   nmcli dev status
   nmcli general status
   nmcli con show labs-primary | grep 802-3-ethernet.mtu
   
EOS
      ;;
    6) cat <<'EOS'
Goal: Set IPv4 DNS on 'labs-primary' via NM.
1) Configure DNS and ignore auto-DNS:
   nmcli con modify labs-primary ipv4.dns "1.1.1.1 8.8.8.8" ipv4.ignore-auto-dns yes
   nmcli con up labs-primary
2) Verify:
   nmcli -g ip4.dns connection show labs-primary
   nmcli -g ipv4.ignore-auto-dns connection show labs-primary
EOS
      ;;
    7) cat <<'EOS'
Goal: Persistent loopback extra IPs via systemd-networkd.
1) Create /etc/systemd/network/10-section2-lo.network:
   sudo tee /etc/systemd/network/10-section2-lo.network >/dev/null <<'NET'
[Match]
Name=lo
[Network]
Address=127.0.0.2/8
Address=127.0.0.3/8
NET
2) Enable & restart networkd:
   sudo systemctl enable --now systemd-networkd
   sudo systemctl restart systemd-networkd
3) Verify:
   ip -4 addr show dev lo | grep 127.0.0.2
   ip -4 addr show dev lo | grep 127.0.0.3
EOS
      ;;
    *) echo -e "${FAIL} Unknown lab $lab"; return 1 ;;
  esac
  echo "----------------------------------------"
}

# =========================
# TIPS
# =========================
print_tip() {
  local lab="$1"
  echo -e "${BOLD}Tips for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1) echo "Use netplan 'match.macaddress' with 'set-name:' to pin a stable name (lan0). After applying, verify link name and IPv4." ;;
    2) echo "Same pattern as Lab 1 but naming to 'wan0'. Ensure MAC matches the intended NIC." ;;
    3) echo "VLANs in netplan use 'vlans:' with 'id' and 'link'. Use 'ip -d link show <vlan>' to inspect VLAN metadata." ;;
    4) echo "If nmcli errors, confirm NetworkManager is installed/active and netplan’s renderer is 'NetworkManager'." ;;
    5) echo "MTU changes via NM take effect when the connection is (re)activated with 'nmcli con up'." ;;
    6) echo "Set multiple DNS servers with a space-separated list; enable 'ipv4.ignore-auto-dns yes' to prefer manual DNS." ;;
    7) echo "systemd-networkd can persist multiple 127.x addresses on 'lo' via a .network file." ;;
    *) echo -e "${FAIL} Unknown lab $lab"; return 1 ;;
  esac
  echo "----------------------------------------"
}

# =========================
# INTERACTIVE MENU
# =========================
interactive_menu() {
  while true; do
    clear
    echo -e "${BOLD}Section 2 Labs Menu${NC}"
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
      1) read -rp "Lab (1-7): " lab; read -rp "Server role (1 or 2): " role; summary_for_lab "$lab"; apply_lab "$lab" "$role"; read -rp "Press Enter..." ;;
      2) read -rp "Lab (1-7): " lab; do_check "$lab"; read -rp "Press Enter..." ;;
      3) reset_all; read -rp "Press Enter..." ;;
      4) status; read -rp "Press Enter..." ;;
      5) print_list; read -rp "Press Enter..." ;;
      6) read -rp "Lab (1-7): " lab; clear; print_solution "$lab"; read -rp "Press Enter..." ;;
      7) read -rp "Lab (1-7): " lab; clear; print_tip "$lab"; read -rp "Press Enter..." ;;
      q|Q) exit 0 ;;
      *) echo "Invalid selection"; sleep 1 ;;
    esac
  done
}

# =========================
# MAIN
# =========================
main() {
  need_root
  mkdirs
  if [[ $# -lt 1 ]]; then interactive_menu; exit 0; fi
  case "$1" in
    list) print_list; exit 0 ;;
    status) status; exit 0 ;;
    reset) reset_all; exit 0 ;;
    solutions)
      [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }
      print_solution "$2"; exit 0 ;;
    tips)
      [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 tips <lab#>"; exit 2; }
      print_tip "$2"; exit 0 ;;
  esac
  local lab="$1"
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 <lab#> apply|check [role]"; exit 2; }
  case "$2" in
    apply)
      [[ $# -lt 3 ]] && { echo -e "${FAIL} Missing role. Use: 1 or 2"; exit 2; }
      summary_for_lab "$lab"
      apply_lab "$lab" "$3"
      ;;
    check)
      do_check "$lab"
      ;;
    *) echo -e "${FAIL} Use: apply | check"; exit 2 ;;
  esac
}
main "$@"
