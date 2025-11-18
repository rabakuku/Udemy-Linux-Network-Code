#!/usr/bin/env bash

# --- Strict mode + helpful trap ---
if [[ -n "${LABS_DEBUG:-}" ]]; then set -x; fi
set -Eeuo pipefail
trap 'echo -e "\e[31m✗\e[0m Error on line $LINENO while running: ${BASH_COMMAND}" >&2' ERR

# ====== User-tunable variables ======
S1_HOST="srv1"
S2_HOST="srv2"
S1_IP="10.10.20.11"
S2_IP="10.10.20.12"
PREFIX="24"
GOOD_MTU="1500"
JUMBO_MTU="9000"

# ====== Paths / State ======
LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"
HOSTS_BAK="${LAB_ROOT}/hosts.bak"
NETPLAN_DIR="/etc/netplan"
LAB_NETPLAN="${NETPLAN_DIR}/10-labs-ens4.yaml"
NETPLAN_BUNDLE_BACKUP="${LAB_ROOT}/netplan-backups"
RENDERER="networkd"

# ====== Colors / Symbols ======
GREEN="\e[32m"; RED="\e[31m"; YELLOW="\e[33m"; BLUE="\e[34m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"
INFO="${BLUE}[i]${NC}"; WARN="${YELLOW}[!]${NC}"

# ====== Helpers ======
need_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo -e "${WARN} Please run as root: sudo $0 $*"
    exit 1
  fi
}

ensure_ens4() {
  if ! ip link show ens4 >/dev/null 2>&1; then
    echo -e "${WARN} Network interface 'ens4' not found."
    if [[ -z "${LABS_FORCE:-}" ]]; then
      if [[ -t 0 && -z "${NONINTERACTIVE:-}" ]]; then
        read -rp "Press Enter to continue anyway, or Ctrl+C to abort... " _
      else
        exit 1
      fi
    fi
  fi
}

mkdirs() { mkdir -p "$LAB_ROOT" "$NETPLAN_BUNDLE_BACKUP"; }
timestamp() { date +"%Y%m%d-%H%M%S"; }

save_state() {
  local key="$1" val="$2"
  mkdirs
  touch "$STATE_FILE"
  if grep -q "^${key}=" "$STATE_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$STATE_FILE"
  else
    echo "${key}=${val}" >> "$STATE_FILE"
  fi
}

get_state() {
  local key="$1"
  [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
  grep "^${key}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true
}

detect_or_get_role() {
  local role
  role="$(get_state role || true || echo "")"
  if [[ -n "${role}" ]]; then echo "$role"; return 0; fi
  local ip
  ip="$(ip -4 -o addr show dev ens4 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
  if [[ "${ip:-}" == "$S1_IP" ]]; then echo 1; return 0; fi
  if [[ "${ip:-}" == "$S2_IP" ]]; then echo 2; return 0; fi
  echo ""
}

backup_netplan_once() {
  mkdirs
  if [[ ! -f "${NETPLAN_BUNDLE_BACKUP}/bundle-INITIAL.tgz" ]]; then
    tar -C "$NETPLAN_DIR" -czf "${NETPLAN_BUNDLE_BACKUP}/bundle-INITIAL.tgz" . 2>/dev/null || true
    echo -e "${INFO} Backed up netplan to ${NETPLAN_BUNDLE_BACKUP}/bundle-INITIAL.tgz"
  fi
}

backup_hosts_once() {
  mkdirs
  if [[ ! -f "$HOSTS_BAK" && -f /etc/hosts ]]; then
    cp -a /etc/hosts "$HOSTS_BAK"
    echo -e "${INFO} Backed up /etc/hosts to $HOSTS_BAK"
  fi
}

fix_netplan_perms() {
  if [[ -d "$NETPLAN_DIR" ]]; then chmod 755 "$NETPLAN_DIR" || true; fi
  if [[ -f "$LAB_NETPLAN" ]]; then chown root:root "$LAB_NETPLAN" || true; chmod 600 "$LAB_NETPLAN" || true; fi
}

write_yaml_from_func() {
  local fn="$1"; shift
  local old_umask
  old_umask=$(umask)
  umask 177
  "$fn" "$@" > "$LAB_NETPLAN"
  umask "$old_umask"
  fix_netplan_perms
}

netplan_apply() {
  fix_netplan_perms
  if command -v netplan >/dev/null 2>&1; then
    netplan generate
    netplan apply
  else
    echo -e "${WARN} 'netplan' not found; skipping apply"
  fi
}

set_hostname_if_needed() {
  local role="$1"
  local desired="$S1_HOST"; [[ "$role" == "2" ]] && desired="$S2_HOST"
  if command -v hostnamectl >/dev/null 2>&1; then
    if [[ "$(hostnamectl --static 2>/dev/null || echo "")" != "$desired" ]]; then
      hostnamectl set-hostname "$desired" || true
      echo -e "${INFO} Hostname set to ${desired}"
    fi
  fi
}

# ====== Good base config ======
good_netplan_yaml() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${ip}/${PREFIX} ]
      mtu: ${GOOD_MTU}
EOF
}

# ====== Labs 1–8 ======
lab1_yaml_no_ip() {
  cat <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens4:
      dhcp4: false
EOF
}

lab2_yaml_wrong_subnet() {
  local role="$1"
  local last="11"; [[ "$role" == "2" ]] && last="12"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ 10.10.21.${last}/${PREFIX} ]
      mtu: ${GOOD_MTU}
EOF
}

lab3_yaml_wrong_mask() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${ip}/32 ]
      mtu: ${GOOD_MTU}
EOF
}

lab4_yaml_wrong_ifname() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens5:
      dhcp4: false
      addresses: [ ${ip}/${PREFIX} ]
      mtu: ${GOOD_MTU}
EOF
}

lab5_yaml_mtu_mismatch() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${ip}/${PREFIX} ]
      mtu: ${JUMBO_MTU}
EOF
}

lab6_yaml_bad_host_route() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${ip}/${PREFIX} ]
      mtu: ${GOOD_MTU}
      activation-mode: off
EOF
}

lab7_yaml_unreachable_local() {
  local role="$1"
  local ip="$S1_IP"; [[ "$role" == "2" ]] && ip="$S2_IP"
  cat <<EOF
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens5:
      dhcp4: false
      addresses: [ ${ip}/32 ]
      mtu: ${GOOD_MTU}
      activation-mode: off
EOF
}

lab8_inject_bad_arp() {
  local role="$1"
  local peer_ip="$S2_IP"; [[ "$role" == "2" ]] && peer_ip="$S1_IP"
  ip neigh replace "${peer_ip}" lladdr 00:11:22:33:44:55 nud permanent dev ens4 || true
}

# ====== Apply Lab ======
apply_lab() {
  local lab="$1" role="$2"
  ensure_ens4
  backup_netplan_once
  backup_hosts_once
  set_hostname_if_needed "$role"
  write_yaml_from_func good_netplan_yaml "$role"

  case "$lab" in
    1) write_yaml_from_func lab1_yaml_no_ip ;;
    2) write_yaml_from_func lab2_yaml_wrong_subnet "$role" ;;
    3) write_yaml_from_func lab3_yaml_wrong_mask "$role" ;;
    4) write_yaml_from_func lab4_yaml_wrong_ifname "$role" ;;
    5) write_yaml_from_func lab5_yaml_mtu_mismatch "$role" ;;
    6) write_yaml_from_func lab6_yaml_bad_host_route "$role" ;;
    7) write_yaml_from_func lab7_yaml_unreachable_local "$role" ;;
    8) write_yaml_from_func good_netplan_yaml "$role" ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac

  netplan_apply || { echo -e "${FAIL} netplan apply failed"; exit 3; }
  [[ "$lab" -eq 8 ]] && lab8_inject_bad_arp "$role"
  save_state role "$role"
  save_state lab "$lab"
  echo -e "${OK} Applied Lab ${lab} for Server ${role}"
}

# ====== Reset ======
reset_all() {
  ensure_ens4
  local role; role=$(detect_or_get_role)
  if [[ -z "${role}" ]]; then
    echo -e "${WARN} Role unknown. Use: $0 set-role 1|2, then run reset again."
    exit 1
  fi
  write_yaml_from_func good_netplan_yaml "$role"
  netplan_apply || true
  if [[ -f "$HOSTS_BAK" ]]; then cp -a "$HOSTS_BAK" /etc/hosts; fi
  local peer_ip="$S2_IP"; [[ "$role" == "2" ]] && peer_ip="$S1_IP"
  ip neigh del "${peer_ip}" dev ens4 2>/dev/null || true
  save_state lab "0"
  echo -e "${OK} Reset complete for Server ${role}"
}

# ====== Check ======
do_check() {
  ensure_ens4
  local lab="$1"
  local role; role=$(detect_or_get_role)
  [[ -z "${role}" ]] && { echo -e "${FAIL} Role unknown"; exit 1; }
  local target_ip="$S2_IP"; [[ "$role" == "2" ]] && target_ip="$S1_IP"

  case "$lab" in
    5)
      echo -e "${INFO} Checking MTU path..."
      if ping -M do -s 2000 -c1 -W3 "${target_ip}" >/dev/null 2>&1; then
        echo -e "${OK} MTU OK"; exit 0
      else
        echo -e "${FAIL} MTU check failed"; exit 4
      fi
      ;;
    *)
      echo -e "${INFO} Checking IP ping..."
      if ping -c1 -W2 "${target_ip}" >/dev/null 2>&1; then
        echo -e "${OK} Peer reachable"; exit 0
      else
        echo -e "${FAIL} Peer unreachable"; exit 4
      fi
      ;;
  esac
}

# ====== Solutions Printer ======
print_solution() {
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1)
      cat <<EOF
Issue: ens4 has no IPv4 address (dhcp4: false; addresses missing).

Fix (persistent via netplan):
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # Use ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}   # (on Server 1; reverse on Server 2)

(Temporary alternative, no file edit):
  sudo ip addr add ${S1_IP}/${PREFIX} dev ens4   # or ${S2_IP}/${PREFIX}
  sudo ip link set ens4 up
EOF
      ;;
    2)
      cat <<EOF
Issue: Wrong subnet (10.10.21.0/24 instead of 10.10.20.0/24).

Fix:
  sudo sed -i 's/10\\.10\\.21\\.[0-9]\\+\\/${PREFIX}/10.10.20.\\1\\/${PREFIX}/g' ${LAB_NETPLAN} || true
  # or rewrite explicitly:
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}
EOF
      ;;
    3)
      cat <<EOF
Issue: Wrong mask (/32). Host cannot reach peer.

Fix:
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}
EOF
      ;;
    4)
      cat <<EOF
Issue: Wrong interface name (ens5). ens4 is the actual NIC.

Fix:
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:                            # corrected name
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}
EOF
      ;;
    5)
      cat <<EOF
Issue: MTU mismatch (jumbo set locally). Check uses: ping -M do -s 2000.
To PASS the check, BOTH servers must support >2000 MTU on ens4.

Option A (recommended): enable jumbo on BOTH servers
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${JUMBO_MTU}
YAML
  sudo netplan generate && sudo netplan apply
  # repeat on the peer server with its IP

Option B (restore standard MTU; will FAIL the lab5 check by design)
  set mtu: ${GOOD_MTU} on both ends.

Verify (after jumbo on both):
  ip link show ens4 | grep -i mtu
  ping -M do -s 2000 -c1 -W3 ${S2_IP}
EOF
      ;;
    6)
      cat <<EOF
Issue: Interface activation disabled (activation-mode: off).

Fix:
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
      # activation-mode removed (defaults to 'manual'/normal bring-up)
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}
EOF
      ;;
    7)
      cat <<EOF
Issue: Multiple issues: wrong ifname (ens5), /32 mask, and activation disabled.

Fix:
  sudo tee ${LAB_NETPLAN} >/dev/null <<'YAML'
network:
  version: 2
  renderer: ${RENDERER}
  ethernets:
    ens4:                            # corrected name
      dhcp4: false
      addresses: [ ${S1_IP}/${PREFIX} ]   # ${S2_IP}/${PREFIX} on Server 2
      mtu: ${GOOD_MTU}
      # activation-mode removed
YAML
  sudo netplan generate && sudo netplan apply

Verify:
  ip -4 -o addr show dev ens4
  ping -c1 ${S2_IP}
EOF
      ;;
    8)
      cat <<EOF
Issue: Poisoned ARP/neighbor entry for the peer IP.

Fix (runtime):
  ip neigh show to ${S2_IP} dev ens4   # (on Server 1; reverse on Server 2)
  sudo ip neigh del ${S2_IP} dev ens4  # delete the bad static entry
  # If needed, clear all for the interface:
  # sudo ip neigh flush dev ens4

Verify:
  ping -c1 ${S2_IP}
  ip neigh show to ${S2_IP} dev ens4
EOF
      ;;
    *)
      echo -e "${FAIL} Unknown lab $lab"; return 1 ;;
  esac
  echo "----------------------------------------"
}

# ====== Status ======
status() {
  ensure_ens4
  local role lab
  role="$(get_state role || true || echo "")"
  lab="$(get_state lab || true || echo "")"
  [[ -z "${role}" ]] && role="(unknown)"
  [[ -z "${lab}"  ]] && lab="(none)"
  echo -e "${INFO} Role: ${role}, Current Lab: ${lab}"
  echo -e "${INFO} ens4 IP(s):"; ip -4 -o addr show dev ens4 2>/dev/null || true
  echo -e "${INFO} Routes on ens4:"; ip route show dev ens4 2>/dev/null || true
}

# ====== Display ======
print_list() {
  cat <<EOF
${BOLD}Linux Networking Labs (ens4)${NC}
1. easy
2. check IP
3. Wrong something
4. check names
5. something is mismatch
6. check the interace
7. Multiple issues
8. Hard one.. good luck

Usage:
  sudo $0 <lab#> 1|2
  sudo $0 <lab#> check
  sudo $0 solutions <lab#>
  sudo $0 reset
  sudo $0 status
  sudo $0 list
EOF
}

# ====== Interactive Menu ======
interactive_menu() {
  NONINTERACTIVE=1 ensure_ens4 || true
  while true; do
    clear
    echo -e "${BOLD}Linux Networking Labs Menu${NC}"
    echo "1) Apply Lab [choose 1..8 & server]"
    echo "2) Check Lab"
    echo "3) Reset"
    echo "4) Status"
    echo "5) List Labs"
    echo "6) Solutions (view step-by-step commands)"
    echo "q) Quit"
    read -rp "Select option: " opt || exit 0
    case "$opt" in
      1)
        read -rp "Lab number (1-8): " lab
        read -rp "Server (1 or 2): " role
        "$0" "$lab" "$role"
        read -rp "Press Enter to continue..." _
        ;;
      2)
        read -rp "Lab number (1-8): " lab
        "$0" "$lab" check
        read -rp "Press Enter to continue..." _
        ;;
      3)
        "$0" reset
        read -rp "Press Enter to continue..." _
        ;;
      4)
        "$0" status
        read -rp "Press Enter to continue..." _
        ;;
      5)
        print_list
        read -rp "Press Enter to continue..." _
        ;;
      6)
        read -rp "Show solution for lab (1-8): " lab
        clear
        print_solution "$lab" || true
        echo
        read -rp "Press Enter to continue..." _
        ;;
      q|Q)
        exit 0
        ;;
      *)
        echo "Invalid selection"
        sleep 1
        ;;
    esac
  done
}

# ====== Main ======
main() {
  need_root
  mkdirs
  [[ $# -lt 1 ]] && { interactive_menu; exit 0; }
  case "$1" in
    list) print_list; exit 0 ;;
    status) status; exit 0 ;;
    reset) reset_all; exit 0 ;;
    set-role)
      [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 set-role 1|2"; exit 2; }
      [[ "$2" != "1" && "$2" != "2" ]] && { echo -e "${FAIL} Role must be 1 or 2"; exit 2; }
      save_state role "$2"; echo -e "${OK} Role set to $2"; exit 0 ;;
    solutions)
      [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }
      print_solution "$2"; exit 0 ;;
  esac
  local lab="$1"
  if ! [[ "$lab" =~ ^[0-9]+$ ]] || (( lab < 1 || lab > 8 )); then
    echo -e "${FAIL} Lab must be 1..8"; exit 2
  fi
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Missing second argument"; exit 2; }
  case "$2" in
    1|2) apply_lab "$lab" "$2" ;;
    check) do_check "$lab" ;;
    *) echo -e "${FAIL} Second argument must be 1, 2, or 'check'"; exit 2 ;;
  esac
}

main "$@"x
