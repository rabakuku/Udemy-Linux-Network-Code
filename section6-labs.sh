
#!/usr/bin/env bash
# If not executed by bash (e.g., /bin/sh), re-exec with bash.
[ -n "$BASH_VERSION" ] || exec /usr/bin/env bash "$0" "$@"

# ============================================================
# Section 6 — IPsec / StrongSwan Tunnel Labs (Interactive Menu)
# ============================================================

# ---- Root check ----
if [ "$(id -u)" -ne 0 ]; then
  echo -e "\e[33m[!] Please run as root: sudo $0 $*\e[0m"
  exit 1
fi

# ---- Strict mode & optional debug ----
[[ -n "${LABS_DEBUG:-}" ]] && set -x
set -Eeuo pipefail
trap 'rc=$?; if [[ $rc -ne 0 ]]; then
  echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2
fi' ERR

# ---- Constants / Paths ----
LAB_ROOT="/etc/labs-menu-section6"
STATE_FILE="${LAB_ROOT}/state"

# Network constants
IFACE="ens4"
S1_IF="10.10.10.1"
S2_IF="10.10.10.2"
S1_LO="172.16.1.1"
S2_LO="172.16.1.2"

# Colors/icons
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"

# Config paths
LIBRE_MAIN="/etc/ipsec.conf"                # Libreswan starter file
LIBRE_CONN="/etc/ipsec.d/section6.conf"     # Per-lab Libreswan conn
LIBRE_SECRETS="/etc/ipsec.secrets"

STRONG_MAIN="/etc/ipsec.conf"               # StrongSwan (legacy) starter file
STRONG_SECRETS="/etc/ipsec.secrets"
STRONG_UNIT="strongswan-starter.service"    # Debian/Ubuntu starter
LIBRE_UNIT="ipsec.service"                  # Libreswan systemd unit

# ---- Helpers ----
has_cmd() { command -v "$1" >/dev/null 2>&1; }
q() { "$@" >/dev/null 2>&1 || true; }
mkdirs() { mkdir -p "$LAB_ROOT"; }
save_state() {
  local k="$1" v="$2"; mkdirs; touch "$STATE_FILE"
  if grep -q "^${k}=" "$STATE_FILE"; then
    sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE"
  else
    echo "${k}=${v}" >> "$STATE_FILE"
  fi
}
get_state() {
  local k="$1"
  [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
  grep "^${k}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true
}
good() { echo -e "${OK} $*"; }
miss() { echo -e "${FAIL} $*"; FAILS=$((FAILS+1)); }
begin_check() { FAILS=0; }
end_check() {
  if [[ ${FAILS:-0} -eq 0 ]]; then
    echo -e "${OK} Good job!!"
  else
    echo -e "${FAIL} ${FAILS} issue(s) found"; exit 4
  fi
}
write_file() { # write_file <path> <mode>; content from stdin
  local path="$1" mode="$2"
  umask 022
  cat >"$path"
  chmod "$mode" "$path" || true
  chown root:root "$path" || true
}
iface_ip() {
  ip -4 addr show "$1" \
    | awk '/inet /{print $2}' \
    | cut -d/ -f1 \
    | head -n1
}

# ---- Package / service helpers ----
ensure_libreswan() {
  # Libreswan conflicts with strongswan-starter; stop strongswan if present
  q systemctl stop "$STRONG_UNIT"
  q apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libreswan iproute2 ufw libnss3-tools
  # Seed minimal starter
  if [[ ! -f "$LIBRE_MAIN" ]] || ! grep -q 'include /etc/ipsec.d/*.conf' "$LIBRE_MAIN"; then
    write_file "$LIBRE_MAIN" 0644 <<'EOF'
config setup
include /etc/ipsec.d/*.conf
EOF
  fi
}

ensure_strongswan() {
  # Avoid conflicts with libreswan
  q systemctl stop "$LIBRE_UNIT"
  q apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends strongswan iproute2 ufw
}

enable_service() {
  local unit="$1"
  q systemctl enable "$unit"
  systemctl restart "$unit" || {
    echo -e "\e[33m[!] ${unit} restart failed. Journal (last 50 lines):\e[0m"
    journalctl -u "$unit" -n 50 --no-pager || true
  }
}

disable_service() {
  local unit="$1"
  q systemctl stop "$unit"
  q systemctl disable "$unit"
}

# ---- Firewall helpers ----
ufw_block_ipsec() {
  if has_cmd ufw; then
    q ufw --force enable
    ufw deny 500/udp || true
    ufw deny 4500/udp || true
  else
    echo -e "${INFO} UFW not installed — skipping UDP/500/4500 DENY."
  fi
}
ufw_allow_ipsec() {
  if has_cmd ufw; then
    q ufw --force enable
    ufw delete deny 500/udp 2>/dev/null || true
    ufw delete deny 4500/udp 2>/dev/null || true
    ufw allow 500/udp || true
    ufw allow 4500/udp || true
  else
    echo -e "${INFO} UFW not installed — skipping UDP/500/4500 ALLOW."
  fi
}

block_icmp() {
  if has_cmd iptables; then
    iptables -I INPUT -p icmp -j DROP || true
  else
    echo -e "${INFO} iptables not available — skipping ICMP block."
  fi
}
unblock_icmp() {
  if has_cmd iptables; then
    while iptables -C INPUT -p icmp -j DROP 2>/dev/null; do
      iptables -D INPUT -p icmp -j DROP || true
    done
  fi
}

# ---- Netplan YAML (always included in solutions) ----
print_netplan_yaml() {
  local server="$1"
  if [[ "$server" == "1" ]]; then
    cat <<EOF
section6-server1.yaml
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - ${S1_IF}/24
    lo:
      addresses:
        - ${S1_LO}/32
netplan apply
EOF
  else
    cat <<EOF
section6-server2.yaml
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - ${S2_IF}/24
    lo:
      addresses:
        - ${S2_LO}/32
netplan apply
EOF
  fi
}

# ---- Lab list (generic titles, with Troubleshooting numbering) ----
print_list() {
  cat <<'EOF'
Section 6 Labs — IPsec/StrongSwan Tunnels
1. Scenario One
2. Scenario Two
3. Troubleshooting 1
4. Troubleshooting 2
5. Troubleshooting 3
6. Scenario Six
7. Scenario Seven
8. Troubleshooting 4
9. Troubleshooting 5
10. Troubleshooting 6

Usage:
  sudo section6-labs.sh <lab#> apply
  sudo section6-labs.sh <lab#> check
  sudo section6-labs.sh reset
  sudo section6-labs.sh status
  sudo section6-labs.sh list
  sudo section6-labs.sh solutions <lab#>
  sudo section6-labs.sh menu   # interactive menu
EOF
}

# ============================================================
# APPLY (config vs troubleshooting)
# ============================================================

# Lab 1: Regular IPsec PSK (Libreswan) — no changes applied
lab1_apply() {
  echo "Lab 1 (Config): Review steps below (no changes applied)."
  print_netplan_yaml 1
  print_netplan_yaml 2
  cat <<EOF
- Build a site-to-site IPsec tunnel with IKEv2 PSK, AES-256/SHA-256, DH modp2048 (PFS).
- Protect ${S1_LO}/32 <-> ${S2_LO}/32 via ${IFACE} (${S1_IF} <-> ${S2_IF}).
- Allow UDP/500 & UDP/4500; ensure DPD restart and auto=start.
EOF
}

# Lab 2: Regular IPsec RSA/cert (Libreswan) — no changes applied
lab2_apply() {
  echo "Lab 2 (Config): Review steps below (no changes applied)."
  print_netplan_yaml 1
  print_netplan_yaml 2
  cat <<EOF
- Site-to-site IPsec with IKEv2 RSA/cert authentication (no StrongSwan).
- Use AES-256/SHA-256, DH modp2048 (PFS), protect ${S1_LO}/32 <-> ${S2_LO}/32.
- Create CA + host certs, import into Libreswan's NSS DB; authby=rsasig; leftrsasigkey/right rsasig key as %cert.
- Open UDP/500 & UDP/4500; auto=start.
EOF
}

# Lab 3: Troubleshooting (wrong tunnel IP + mismatched encryption) — Libreswan
lab3_apply() {
  echo "Lab 3 (Troubleshooting): applying wrong tunnel identity + weak proposals."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab3
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_LO}/32
  right=${S2_IF}
  rightid=10.1.2.2          # WRONG: tunnel ID
  rightsubnet=${S2_LO}/32
  authby=secret
  ike=aes128-sha2_256-modp1024!   # WRONG / weak
  esp=aes128-sha2_256!
  pfs=yes
  ikelifetime=1h
  salifetime=8h
  dpddelay=30s
  dpdtimeout=120s
  dpdaction=restart
  auto=start
EOF
  write_file "$LIBRE_SECRETS" 0600 <<EOF
${S1_IF} ${S2_IF} : PSK "supersecret"
EOF
  enable_service "$LIBRE_UNIT"
  ufw_allow_ipsec
  echo -e "${OK} Faulty Libreswan config written to ${LIBRE_CONN}."
}

# Lab 4: Troubleshooting (wrong port + mismatch auth) — Libreswan
lab4_apply() {
  echo "Lab 4 (Troubleshooting): applying RSA auth without certs + blocking IKE ports."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab4
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_LO}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_LO}/32
  authby=rsasig          # WRONG: RSA without certs
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  pfs=yes
  auto=start
EOF
  write_file "$LIBRE_SECRETS" 0600 <<EOF
# Intentionally incompatible with rsasig
EOF
  enable_service "$LIBRE_UNIT"
  ufw_block_ipsec         # simulate wrong listening port by blocking 500/4500
  echo -e "${OK} Deployed mismatched auth and blocked UDP/500/4500."
}

# Lab 5: Troubleshooting (wrong lo IP + mismatched auth/crypto + firewall blocks) — Libreswan
lab5_apply() {
  echo "Lab 5 (Troubleshooting): applying multiple faults + blocking IKE ports."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab5
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=172.16.9.1/32    # WRONG loopback
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=172.16.9.2/32   # WRONG loopback
  authby=rsasig               # WRONG auth (no certs)
  ike=aes128-sha1-modp1024!   # WRONG/legacy
  esp=3des-sha1!              # WRONG/legacy
  pfs=no
  auto=start
EOF
  write_file "$LIBRE_SECRETS" 0600 <<EOF
${S1_IF} ${S2_IF} : PSK "supersecret"
EOF
  enable_service "$LIBRE_UNIT"
  ufw_block_ipsec
  echo -e "${OK} Faulty config deployed and IKE ports blocked."
}

# Lab 6: Regular StrongSwan PSK — no changes applied
lab6_apply() {
  echo "Lab 6 (Config): Review steps below (no changes applied)."
  print_netplan_yaml 1
  print_netplan_yaml 2
  cat <<EOF
- Site-to-site StrongSwan with IKEv2 PSK, AES-256/SHA-256, DH modp2048 (PFS).
- Protect ${S1_LO}/32 <-> ${S2_LO}/32 via ${IFACE} (${S1_IF} <-> ${S2_IF}).
- Open UDP/500 & UDP/4500; auto=start.
EOF
}

# Lab 7: Regular StrongSwan RSA/cert — no changes applied
lab7_apply() {
  echo "Lab 7 (Config): Review steps below (no changes applied)."
  print_netplan_yaml 1
  print_netplan_yaml 2
  cat <<EOF
- Site-to-site StrongSwan with IKEv2 RSA/cert authentication.
- AES-256/SHA-256, DH modp2048 (PFS), protect ${S1_LO}/32 <-> ${S2_LO}/32.
- Generate CA + host certs (ipsec pki); place in /etc/ipsec.d/{cacerts,certs,private}; set authby=rsasig and leftcert/rightcert.
EOF
}

# Lab 8: Troubleshooting StrongSwan (mismatch auth + mismatch encryption)
lab8_apply() {
  echo "Lab 8 (Troubleshooting StrongSwan): applying RSA auth without certs + weak proposals."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"

conn s6-lab8
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_LO}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_LO}/32
  authby=rsasig                # WRONG auth (no certs)
  ike=aes128-sha1-modp1024!    # WRONG/weak
  esp=aes128-sha1!             # WRONG
  auto=start
EOF
  write_file "$STRONG_SECRETS" 0600 <<EOF
# Empty; RSA selected with no certs to force mismatch
EOF
  enable_service "$STRONG_UNIT"
  ufw_allow_ipsec
  echo -e "${OK} StrongSwan with mismatched auth/crypto deployed."
}

# Lab 9: Troubleshooting StrongSwan (wrong lo IP + wrong tun ID)
lab9_apply() {
  echo "Lab 9 (Troubleshooting StrongSwan): applying wrong loopbacks + wrong IDs."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"

conn s6-lab9
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=10.1.2.1               # WRONG ID
  leftsubnet=172.16.9.1/32      # WRONG loopback
  right=${S2_IF}
  rightid=10.1.2.2               # WRONG ID
  rightsubnet=172.16.9.2/32      # WRONG loopback
  authby=secret
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  auto=start
EOF
  write_file "$STRONG_SECRETS" 0600 <<EOF
${S1_IF} ${S2_IF} : PSK "supersecret"
EOF
  enable_service "$STRONG_UNIT"
  ufw_allow_ipsec
  echo -e "${OK} StrongSwan config with wrong IDs/loopbacks written."
}

# Lab 10: Troubleshooting StrongSwan (mismatch encryption + ICMP blocked)
lab10_apply() {
  echo "Lab 10 (Troubleshooting StrongSwan): applying weak proposals + blocking ICMP."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"

conn s6-lab10
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_LO}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_LO}/32
  authby=secret
  ike=aes128-sha1-modp1024!     # WRONG/weak
  esp=aes128-sha1!              # WRONG
  auto=start
EOF
  write_file "$STRONG_SECRETS" 0600 <<EOF
${S1_IF} ${S2_IF} : PSK "supersecret"
EOF
  enable_service "$STRONG_UNIT"
  ufw_allow_ipsec
  block_icmp
  echo -e "${OK} StrongSwan with weak crypto and ICMP blocked applied."
}

apply_lab() {
  local lab="$1"
  case "$lab" in
    1) lab1_apply ;;
    2) lab2_apply ;;
    3) lab3_apply ;;
    4) lab4_apply ;;
    5) lab5_apply ;;
    6) lab6_apply ;;
    7) lab7_apply ;;
    8) lab8_apply ;;
    9) lab9_apply ;;
    10) lab10_apply ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
  save_state lab "$lab"
  echo -e "${OK} Applied Lab $lab"
}

# ============================================================
# CHECKS
# ============================================================

can_ping() { ping -c1 -W1 "$1" >/dev/null 2>&1; }

lab1_check() {
  begin_check
  can_ping "$S2_LO" && good "peer loopback (${S2_LO}) reachable" || miss "Cannot ping peer loopback"
  can_ping "$S1_LO" && good "local loopback (${S1_LO}) reachable" || miss "Cannot ping local loopback"
  if has_cmd ss; then
    ss -lun | grep -q ':500' && good "UDP/500 listening" || miss "UDP/500 not listening"
    ss -lun | grep -q ':4500' && good "UDP/4500 listening" || miss "UDP/4500 not listening"
  else
    good "Skipping port check (ss not available)"
  fi
  end_check
}

lab2_check() {
  begin_check
  # Just sanity + ping (students configure RSA/cert themselves)
  can_ping "$S2_LO" && good "peer loopback (${S2_LO}) reachable" || miss "Cannot ping peer loopback"
  end_check
}

lab3_check() {
  begin_check
  if [[ -f "$LIBRE_CONN" ]]; then
    grep -q 'ike=aes128' "$LIBRE_CONN" && miss "IKE uses AES-128; fix to AES-256 + modp2048" || good "IKE proposal looks OK"
    grep -q 'esp=aes128' "$LIBRE_CONN" && miss "ESP uses AES-128; fix to AES-256" || good "ESP proposal looks OK"
    grep -q 'rightid=10.1.2.2' "$LIBRE_CONN" && miss "Wrong rightid — set to ${S2_IF}" || good "Peer ID looks OK"
  else
    miss "No ${LIBRE_CONN} found"
  fi
  end_check
}

lab4_check() {
  begin_check
  if [[ -f "$LIBRE_CONN" ]]; then
    grep -q 'authby=rsasig' "$LIBRE_CONN" && miss "Auth mismatch (RSA without certs) — use PSK or configure certs" || good "Auth method looks OK"
  else
    miss "No ${LIBRE_CONN} found"
  fi
  if has_cmd ufw; then
    if ufw status | grep -E '500/udp.*DENY|4500/udp.*DENY' >/dev/null; then
      miss "UFW denies UDP/500 or 4500"
    else
      good "UFW not denying IKE ports"
    fi
  else
    good "Skipping UFW check (ufw not installed)"
  fi
  end_check
}

lab5_check() {
  begin_check
  if [[ -f "$LIBRE_CONN" ]]; then
    grep -q 'leftsubnet=172.16.9.1/32' "$LIBRE_CONN" && miss "Wrong left loopback — ${S1_LO}/32 required" || good "Left loopback looks OK"
    grep -q 'rightsubnet=172.16.9.2/32' "$LIBRE_CONN" && miss "Wrong right loopback — ${S2_LO}/32 required" || good "Right loopback looks OK"
    grep -q 'ike=aes128' "$LIBRE_CONN" && miss "Weak IKE proposal" || good "IKE proposal looks OK"
    grep -q 'esp=3des' "$LIBRE_CONN" && miss "Legacy ESP cipher (3DES)" || good "ESP cipher looks OK"
    grep -q 'authby=rsasig' "$LIBRE_CONN" && miss "Auth mismatch (RSA w/o certs)" || good "Auth method looks OK"
  else
    miss "No ${LIBRE_CONN} found"
  fi
  if has_cmd ufw; then
    ufw status | grep -E '500/udp.*DENY|4500/udp.*DENY' >/dev/null && miss "UFW denies UDP/500 or 4500" || good "UFW not denying IKE ports"
  fi
  end_check
}

lab6_check() {
  begin_check
  can_ping "$S2_LO" && good "peer loopback (${S2_LO}) reachable" || miss "Cannot ping peer loopback"
  if has_cmd ss; then
    ss -lun | grep -q ':500' && good "UDP/500 listening" || miss "UDP/500 not listening"
    ss -lun | grep -q ':4500' && good "UDP/4500 listening" || miss "UDP/4500 not listening"
  else
    good "Skipping port check (ss not available)"
  fi
  end_check
}

lab7_check() {
  begin_check
  can_ping "$S2_LO" && good "peer loopback (${S2_LO}) reachable" || miss "Cannot ping peer loopback"
  end_check
}

lab8_check() {
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'authby=rsasig' "$STRONG_MAIN" && miss "RSA selected without certs — fix to PSK or configure certs" || good "Auth not mismatched"
    grep -q 'ike=aes128' "$STRONG_MAIN" && miss "StrongSwan IKE uses AES-128; fix to AES-256 + modp2048" || good "IKE proposal looks OK"
    grep -q 'esp=aes128' "$STRONG_MAIN" && miss "StrongSwan ESP uses AES-128; fix to AES-256" || good "ESP proposal looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  end_check
}

lab9_check() {
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'leftid=10.1.2.1' "$STRONG_MAIN" && miss "Wrong left ID — use ${S1_IF} or proper identity" || good "Left ID looks OK"
    grep -q 'rightid=10.1.2.2' "$STRONG_MAIN" && miss "Wrong right ID — use ${S2_IF}" || good "Right ID looks OK"
    grep -q 'leftsubnet=172.16.9.1/32' "$STRONG_MAIN" && miss "Wrong left loopback — ${S1_LO}/32 required" || good "Left loopback looks OK"
    grep -q 'rightsubnet=172.16.9.2/32' "$STRONG_MAIN" && miss "Wrong right loopback — ${S2_LO}/32 required" || good "Right loopback looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  end_check
}

lab10_check() {
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'ike=aes128' "$STRONG_MAIN" && miss "StrongSwan IKE uses AES-128; fix to AES-256 + modp2048" || good "IKE proposal looks OK"
    grep -q 'esp=aes128' "$STRONG_MAIN" && miss "StrongSwan ESP uses AES-128; fix to AES-256" || good "ESP proposal looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  if can_ping "$S2_LO"; then
    good "ICMP not blocked; loopback ping works"
  else
    miss "ICMP likely blocked; allow ICMP to pass"
  fi
  end_check
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
    8) lab8_check ;;
    9) lab9_check ;;
    10) lab10_check ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# ============================================================
# SOLUTIONS (full steps & commands; include YAML)
# ============================================================

print_solution() {
  local lab="$1"
  echo "------ Solutions for Lab ${lab} ------"
  case "$lab" in
    1)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Libreswan PSK baseline (IKEv2, AES-256/SHA-256, modp2048, PFS)
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libreswan ufw
sudo ufw --force enable
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

sudo tee /etc/ipsec.conf >/dev/null <<'CONF'
config setup
include /etc/ipsec.d/*.conf
CONF

sudo tee /etc/ipsec.d/section6-lab1.conf >/dev/null <<'CONF'
conn s6-lab1
  type=tunnel
  keyexchange=ikev2
  left=10.10.10.1
  leftid=10.10.10.1
  leftsubnet=172.16.1.1/32
  right=10.10.10.2
  rightid=10.10.10.2
  rightsubnet=172.16.1.2/32
  authby=secret
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  pfs=yes
  ikelifetime=8h
  salifetime=1h
  dpddelay=30s
  dpdtimeout=120s
  dpdaction=restart
  auto=start
CONF

sudo tee /etc/ipsec.secrets >/dev/null <<'CONF'
10.10.10.1 10.10.10.2 : PSK "supersecret"
CONF
sudo chmod 600 /etc/ipsec.secrets

sudo systemctl enable ipsec.service
sudo systemctl restart ipsec.service

ipsec status
sudo ss -lun | grep -E ':500|:4500' || echo "IKE ports not listening"
ping -c2 172.16.1.2
EOS
      ;;
    2)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Libreswan RSA/cert baseline
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libreswan ufw libnss3-tools openssl
sudo ufw --force enable
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

# Initialize NSS DB for Libreswan
sudo ipsec initnss 2>/dev/null || true
# Create CA
openssl req -new -x509 -nodes -newkey rsa:4096 -days 3650 \
  -subj "/CN=Section6-CA" -keyout /etc/ipsec.d/ca.key -out /etc/ipsec.d/ca.crt
# Create server1 key+CSR
openssl req -new -nodes -newkey rsa:3072 \
  -subj "/CN=10.10.10.1" -keyout /etc/ipsec.d/server1.key -out /etc/ipsec.d/server1.csr
openssl x509 -req -in /etc/ipsec.d/server1.csr -CA /etc/ipsec.d/ca.crt -CAkey /etc/ipsec.d/ca.key \
  -CAcreateserial -days 1825 -out /etc/ipsec.d/server1.crt
# Create server2 key+CSR
openssl req -new -nodes -newkey rsa:3072 \
  -subj "/CN=10.10.10.2" -keyout /etc/ipsec.d/server2.key -out /etc/ipsec.d/server2.csr
openssl x509 -req -in /etc/ipsec.d/server2.csr -CA /etc/ipsec.d/ca.crt -CAkey /etc/ipsec.d/ca.key \
  -CAcreateserial -days 1825 -out /etc/ipsec.d/server2.crt

# Package to PKCS12 and import to NSS DB (nicknames: server1, server2)
openssl pkcs12 -export -inkey /etc/ipsec.d/server1.key -in /etc/ipsec.d/server1.crt \
  -certfile /etc/ipsec.d/ca.crt -out /etc/ipsec.d/server1.p12 -passout pass:
openssl pkcs12 -export -inkey /etc/ipsec.d/server2.key -in /etc/ipsec.d/server2.crt \
  -certfile /etc/ipsec.d/ca.crt -out /etc/ipsec.d/server2.p12 -passout pass:

sudo pk12util -i /etc/ipsec.d/server1.p12 -d /etc/ipsec.d -W "" -n "server1"
sudo pk12util -i /etc/ipsec.d/server2.p12 -d /etc/ipsec.d -W "" -n "server2"
sudo certutil -A -n "Section6-CA" -t "CT,C,C" -d /etc/ipsec.d -a -i /etc/ipsec.d/ca.crt

# Libreswan config with RSA/cert
sudo tee /etc/ipsec.conf >/dev/null <<'CONF'
config setup
include /etc/ipsec.d/*.conf
CONF

sudo tee /etc/ipsec.d/section6-lab2.conf >/dev/null <<'CONF'
conn s6-lab2
  type=tunnel
  keyexchange=ikev2
  left=10.10.10.1
  leftid=10.10.10.1
  leftsubnet=172.16.1.1/32
  right=10.10.10.2
  rightid=10.10.10.2
  rightsubnet=172.16.1.2/32
  authby=rsasig
  leftrsasigkey=%cert
  rightrsasigkey=%cert
  leftcert=server1
  rightcert=server2
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  pfs=yes
  auto=start
CONF

sudo systemctl enable ipsec.service
sudo systemctl restart ipsec.service

ipsec status
ping -c2 172.16.1.2
EOS
      ;;
    3)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 1 (Libreswan)
sudo sed -i 's/^  rightid=.*/  rightid=10.10.10.2/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  ike=.*/  ike=aes256-sha2_256-modp2048!/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  esp=.*/  esp=aes256-sha2_256!/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  pfs=.*/  pfs=yes/' /etc/ipsec.d/section6.conf

sudo systemctl restart ipsec.service
ipsec status
ping -c2 172.16.1.2
EOS
      ;;
    4)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 2 (Libreswan)
# Use PSK or set up proper RSA certs
sudo sed -i 's/^  authby=.*/  authby=secret/' /etc/ipsec.d/section6.conf
sudo tee /etc/ipsec.secrets >/dev/null <<'CONF'
10.10.10.1 10.10.10.2 : PSK "supersecret"
CONF
sudo chmod 600 /etc/ipsec.secrets

# Unblock IKE ports
sudo ufw delete deny 500/udp 2>/dev/null || true
sudo ufw delete deny 4500/udp 2>/dev/null || true
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

sudo systemctl restart ipsec.service
ipsec status
ping -c2 172.16.1.2
EOS
      ;;
    5)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 3 (Libreswan)
sudo sed -i 's/^  leftsubnet=.*/  leftsubnet=172.16.1.1\/32/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  rightsubnet=.*/  rightsubnet=172.16.1.2\/32/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  ike=.*/  ike=aes256-sha2_256-modp2048!/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  esp=.*/  esp=aes256-sha2_256!/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  pfs=.*/  pfs=yes/' /etc/ipsec.d/section6.conf
sudo sed -i 's/^  authby=.*/  authby=secret/' /etc/ipsec.d/section6.conf

sudo ufw delete deny 500/udp 2>/dev/null || true
sudo ufw delete deny 4500/udp 2>/dev/null || true
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

sudo systemctl restart ipsec.service
ipsec status
ping -c2 172.16.1.2
EOS
      ;;
    6)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# StrongSwan PSK baseline
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan ufw
sudo ufw --force enable
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

sudo tee /etc/ipsec.conf >/dev/null <<'CONF'
config setup
  charondebug="ike 1, knl 1, cfg 0"

conn s6-lab6
  keyexchange=ikev2
  type=tunnel
  left=10.10.10.1
  leftid=10.10.10.1
  leftsubnet=172.16.1.1/32
  right=10.10.10.2
  rightid=10.10.10.2
  rightsubnet=172.16.1.2/32
  authby=secret
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  dpdaction=restart
  dpddelay=30s
  auto=start
CONF

sudo tee /etc/ipsec.secrets >/dev/null <<'CONF'
10.10.10.1 10.10.10.2 : PSK "supersecret"
CONF
sudo chmod 600 /etc/ipsec.secrets

sudo systemctl enable strongswan-starter.service
sudo systemctl restart strongswan-starter.service

ipsec statusall
ping -c2 172.16.1.2
EOS
      ;;
    7)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# StrongSwan RSA/cert baseline (ipsec pki)
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan ufw
sudo ufw --force enable
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

# Create CA and host certs
mkdir -p /etc/ipsec.d/{cacerts,certs,private}
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca.key.pem
ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca.key.pem \
  --type rsa --dn "CN=Section6-CA" --outform pem > /etc/ipsec.d/cacerts/ca.crt.pem

ipsec pki --gen --type rsa --size 3072 --outform pem > /etc/ipsec.d/private/server1.key.pem
ipsec pki --pub --in /etc/ipsec.d/private/server1.key.pem --type rsa \
  | ipsec pki --issue --lifetime 1825 --cacert /etc/ipsec.d/cacerts/ca.crt.pem \
  --cakey /etc/ipsec.d/private/ca.key.pem --dn "CN=10.10.10.1" --san 10.10.10.1 \
  --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/server1.crt.pem

ipsec pki --gen --type rsa --size 3072 --outform pem > /etc/ipsec.d/private/server2.key.pem
ipsec pki --pub --in /etc/ipsec.d/private/server2.key.pem --type rsa \
  | ipsec pki --issue --lifetime 1825 --cacert /etc/ipsec.d/cacerts/ca.crt.pem \
  --cakey /etc/ipsec.d/private/ca.key.pem --dn "CN=10.10.10.2" --san 10.10.10.2 \
  --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/server2.crt.pem

# StrongSwan RSA config
sudo tee /etc/ipsec.conf >/dev/null <<'CONF'
config setup
  charondebug="ike 1, knl 1, cfg 0"

conn s6-lab7
  keyexchange=ikev2
  type=tunnel
  left=10.10.10.1
  leftid=10.10.10.1
  leftsubnet=172.16.1.1/32
  leftcert=server1.crt.pem
  right=10.10.10.2
  rightid=10.10.10.2
  rightsubnet=172.16.1.2/32
  rightcert=server2.crt.pem
  authby=rsasig
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  auto=start
CONF

sudo systemctl enable strongswan-starter.service
sudo systemctl restart strongswan-starter.service

ipsec statusall
ping -c2 172.16.1.2
EOS
      ;;
    8)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 4 (StrongSwan)
# Use PSK or configure RSA certs properly
sudo sed -i 's/^  authby=.*/  authby=secret/' /etc/ipsec.conf
sudo sed -i 's/^  ike=.*/  ike=aes256-sha2_256-modp2048!/' /etc/ipsec.conf
sudo sed -i 's/^  esp=.*/  esp=aes256-sha2_256!/' /etc/ipsec.conf

sudo tee /etc/ipsec.secrets >/dev/null <<'CONF'
10.10.10.1 10.10.10.2 : PSK "supersecret"
CONF
sudo chmod 600 /etc/ipsec.secrets

sudo systemctl restart strongswan-starter.service
ipsec statusall
ping -c2 172.16.1.2
EOS
      ;;
    9)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 5 (StrongSwan)
sudo sed -i 's/^  leftid=.*/  leftid=10.10.10.1/' /etc/ipsec.conf
sudo sed -i 's/^  rightid=.*/  rightid=10.10.10.2/' /etc/ipsec.conf
sudo sed -i 's/^  leftsubnet=.*/  leftsubnet=172.16.1.1\/32/' /etc/ipsec.conf
sudo sed -i 's/^  rightsubnet=.*/  rightsubnet=172.16.1.2\/32/' /etc/ipsec.conf

sudo systemctl restart strongswan-starter.service
ipsec statusall
ping -c2 172.16.1.2
EOS
      ;;
    10)
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<'EOS'
# Fixes for Troubleshooting 6 (StrongSwan)
sudo sed -i 's/^  ike=.*/  ike=aes256-sha2_256-modp2048!/' /etc/ipsec.conf
sudo sed -i 's/^  esp=.*/  esp=aes256-sha2_256!/' /etc/ipsec.conf

# Unblock ICMP if blocked
sudo iptables -D INPUT -p icmp -j DROP 2>/dev/null || true

sudo systemctl restart strongswan-starter.service
ipsec statusall
ping -c2 172.16.1.2
EOS
      ;;
    *)
      echo -e "${FAIL} Unknown lab ${lab}"
      ;;
  esac
  echo "------------------------------------"
}

# ============================================================
# RESET / STATUS
# ============================================================

reset_all() {
  disable_service "$LIBRE_UNIT"
  disable_service "$STRONG_UNIT"
  if has_cmd ufw; then
    ufw delete deny 500/udp 2>/dev/null || true
    ufw delete deny 4500/udp 2>/dev/null || true
  fi
  unblock_icmp
  rm -f "$LIBRE_CONN" "$STRONG_MAIN" "$STRONG_SECRETS" "$LIBRE_SECRETS"
  : > "$STATE_FILE" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}

status() {
  local lab; lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Libreswan unit: ${LIBRE_UNIT} — $(systemctl is-active "$LIBRE_UNIT" 2>/dev/null || echo inactive)"
  echo -e "${INFO} StrongSwan unit: ${STRONG_UNIT} — $(systemctl is-active "$STRONG_UNIT" 2>/dev/null || echo inactive)"
  echo -e "${INFO} Libreswan conn file: ${LIBRE_CONN} $( [[ -f "$LIBRE_CONN" ]] && echo '[present]' || echo '[missing]' )"
  echo -e "${INFO} StrongSwan conf: ${STRONG_MAIN} $( [[ -f "$STRONG_MAIN" ]] && echo '[present]' || echo '[missing]' )"
  if has_cmd ufw; then
    echo -e "${INFO} UFW status:"; ufw status || true
  else
    echo -e "${INFO} UFW not installed."
  fi
  echo -e "${INFO} Loopback addresses:"; ip addr show lo | sed -n 's/^\s*inet\s\([0-9./]*\).*/\1/p'
  echo -e "${INFO} Interface ${IFACE} IP:"; iface_ip "$IFACE" || true
}

# ============================================================
# INTERACTIVE MENU
# ============================================================

interactive_menu() {
  while true; do
    clear
    echo "=== Section 6 Labs Menu (IPsec / StrongSwan) ==="
    echo "1) Apply Lab"
    echo "2) Check Lab"
    echo "3) Reset"
    echo "4) Status"
    echo "5) List Labs"
    echo "6) Solutions"
    echo "q) Quit"
    read -rp "Select option: " opt
    case "$opt" in
      1)
        read -rp "Lab (1-10): " lab
        apply_lab "$lab"
        read -rp "Press Enter..."
        ;;
      2)
        read -rp "Lab (1-10): " lab
        do_check "$lab"
        read -rp "Press Enter..."
        ;;
      3)
        reset_all
        read -rp "Press Enter..."
        ;;
      4)
        status
        read -rp "Press Enter..."
        ;;
      5)
        print_list
        read -rp "Press Enter..."
        ;;
      6)
        read -rp "Lab (1-10): " lab
        print_solution "$lab"
        read -rp "Press Enter..."
        ;;
      q|Q)
        exit 0
        ;;
      *)
        echo "Invalid selection"; sleep 1
        ;;
    esac
  done
}

# ============================================================
# MAIN
# ============================================================

main() {
  mkdirs
  if [[ $# -lt 1 ]]; then
    interactive_menu
    exit 0
  fi
  case "$1" in
    menu) interactive_menu; exit 0 ;;
    list) print_list; exit 0 ;;
    status) status; exit 0 ;;
    reset) reset_all; exit 0 ;;
    solutions) [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }
      print_solution "$2"; exit 0 ;;
  esac
  local lab="$1"
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 <lab#> apply|check"; exit 2; }
  case "$2" in
    apply) apply_lab "$lab" ;;
    check) do_check "$lab" ;;
    *) echo -e "${FAIL} Use: apply | check"; exit 2 ;;
  esac
}
main "$@"
