
#!/usr/bin/env bash
# If not executed by bash (e.g., /bin/sh), re-exec with bash.
[ -n "$BASH_VERSION" ] || exec /usr/bin/env bash "$0" "$@"

# ============================================================
# Section 6 — IPsec / StrongSwan / WireGuard Tunnel Labs (Interactive Menu)
# Labs 1: Libreswan PSK (config only)
# Lab 2: Libreswan Troubleshooting (was Lab 3)
# Labs 3–5: Libreswan Troubleshooting (shifted down)
# Labs 6–9: StrongSwan (were 7–10)
# Lab 10: WireGuard + IPsec (was 11)
# Lab 11: WireGuard + IPsec Troubleshooting (was 12)
# - Config labs (1,6,10): apply prints steps (does NOT change system)
# - Troubleshooting labs (2,3,4,5,7,8,9,11): apply writes broken configs & toggles firewall
# - Loopbacks routed via tunnel; checks include pinging peer loopback
# - Solutions always include netplan YAML for ens4 + dummy loopback
# ============================================================

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
  echo -e "\e[33m[!] Please run as root: sudo $0 $*\e[0m"
  exit 1
fi

# --- Strict mode & optional debug ---
[[ -n "${LABS_DEBUG:-}" ]] && set -x
set -Eeuo pipefail
trap 'rc=$?; if [[ $rc -ne 0 ]]; then echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2; fi' ERR

# --- Constants / Paths ---
LAB_ROOT="/etc/labs-menu-section6"
STATE_FILE="${LAB_ROOT}/state"

# Network constants
IFACE="ens4"
S1_IF="10.10.10.1"
S2_IF="10.10.10.2"
S1_Dummy="172.16.1.1"
S2_Dummy="172.16.1.2"

# Colors/icons
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"

# Config paths
LIBRE_MAIN="/etc/ipsec.conf"     # Libreswan starter file
LIBRE_CONN="/etc/ipsec.d/section6.conf" # Per-lab Libreswan conn
LIBRE_SECRETS="/etc/ipsec.secrets"

STRONG_MAIN="/etc/ipsec.conf"    # StrongSwan starter file
STRONG_SECRETS="/etc/ipsec.secrets"
STRONG_UNIT="strongswan-starter.service"
LIBRE_UNIT="ipsec.service"

# --- Helpers ---
has_cmd(){ command -v "$1" >/dev/null 2>&1; }
q(){ "$@" >/dev/null 2>&1 || true; }
mkdirs(){ mkdir -p "$LAB_ROOT"; }
save_state(){ local k="$1" v="$2"; mkdirs; touch "$STATE_FILE"
  if grep -q "^${k}=" "$STATE_FILE"; then
    sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE"
  else
    echo "${k}=${v}" >> "$STATE_FILE"
  fi
}
get_state(){ local k="$1"
  [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
  grep "^${k}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true
}
good(){ echo -e "${OK} $*"; }
miss(){ echo -e "${FAIL} $*"; FAILS=$((FAILS+1)); }
begin_check(){ FAILS=0; }
end_check(){
  if [[ ${FAILS:-0} -eq 0 ]]; then
    echo -e "${OK} Good job!!"
  else
    echo -e "${FAIL} ${FAILS} issue(s) found"; exit 4
  fi
}
write_file(){ # write_file <path> <mode>; content from stdin
  local path="$1" mode="$2"
  umask 022
  cat >"$path"
  chmod "$mode" "$path" || true
  chown root:root "$path" || true
}
iface_ip(){ ip -4 addr show "$1" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1; }

# --- Package / service helpers ---
ensure_libreswan(){
  q systemctl stop "$STRONG_UNIT" # avoid conflicts
  q apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libreswan iproute2 ufw libnss3-tools
  if [[ ! -f "$LIBRE_MAIN" ]] || ! grep -q 'include /etc/ipsec.d/*.conf' "$LIBRE_MAIN"; then
    write_file "$LIBRE_MAIN" 0644 <<'EOF'
config setup
include /etc/ipsec.d/*.conf
EOF
  fi
}
ensure_strongswan(){
  q systemctl stop "$LIBRE_UNIT"
  q apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends strongswan iproute2 ufw
}
enable_service(){ local unit="$1"
  q systemctl enable "$unit"
  systemctl restart "$unit" || {
    echo -e "\e[33m[!] ${unit} restart failed. Journal (last 50 lines):\e[0m"
    journalctl -u "$unit" -n 50 --no-pager || true
  }
}
disable_service(){ local unit="$1"
  q systemctl stop "$unit"
  q systemctl disable "$unit"
}

# --- Firewall helpers ---
ufw_block_ipsec(){
  if has_cmd ufw; then
    q ufw --force enable
    ufw deny 500/udp || true
    ufw deny 4500/udp || true
  else
    echo -e "${INFO} UFW not installed — skipping UDP/500/4500 DENY."
  fi
}
ufw_allow_ipsec(){
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
block_icmp(){
  if has_cmd iptables; then
    iptables -I INPUT -p icmp -j DROP || true
  else
    echo -e "${INFO} iptables not available — skipping ICMP block."
  fi
}
unblock_icmp(){
  if has_cmd iptables; then
    while iptables -C INPUT -p icmp -j DROP 2>/dev/null; do
      iptables -D INPUT -p icmp -j DROP || true
    done
  fi
}

# --- Netplan YAML (always included in solutions) ---
print_netplan_yaml_server1(){
  cat <<EOF
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - 10.10.10.1/24
  dummy-devices:
    dummy0:
      addresses:
        - 172.16.1.1/32
EOF
}
print_netplan_yaml_server2(){
  cat <<EOF
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - 10.10.10.2/24
  dummy-devices:
    dummy0:
      addresses:
        - 172.16.1.2/32
EOF
}

# --- Baseline solution block (used for many labs) ---
print_solution_block(){
  cat <<'EOS'
#Configure both servers with:
#server1 netplan
nano /etc/netplan/section6-server1.yaml
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - 10.10.10.1/24
  dummy-devices:
    dummy0:
      addresses:
        - 172.16.1.1/32
netplan apply
#server2 netplan
nano /etc/netplan/section6-server2.yaml
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - 10.10.10.2/24
  dummy-devices:
    dummy0:
      addresses:
        - 172.16.1.2/32
netplan apply
# Libreswan PSK baseline (IKEv2, AES-256/SHA-256, modp2048, PFS)
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libreswan ufw
sudo ufw allow 500/udp
sudo ufw allow 4500/udp
sudo ufw allow 22
sudo ufw --force enable
# IPSEC Config
# Server1
nano /etc/ipsec.conf
config setup
  protostack=netkey
  plutodebug="none"
  logfile=/var/log/pluto.log
include /etc/ipsec.d/*.conf
# Server2
nano /etc/ipsec.conf
config setup
  protostack=netkey
  plutodebug="none"
  logfile=/var/log/pluto.log
include /etc/ipsec.d/*.conf
# server1
sudo ip route add 172.16.1.2/32 via 10.10.10.2
# server2
sudo ip route add 172.16.1.1/32 via 10.10.10.1
# Both servers — IPsec sysctls
sudo tee /etc/sysctl.d/99-libreswan.conf >/dev/null <<'EOF'
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF
sudo sysctl -p /etc/sysctl.d/99-libreswan.conf
sudo tee /etc/sysctl.d/99-ipsec.conf >/dev/null <<'EOF'
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sudo sysctl -p /etc/sysctl.d/99-ipsec.conf
# Example Libreswan conn (PSK)
# server1
nano /etc/ipsec.d/section6-lab1.conf
conn s6-lab1
  type=tunnel
  ikev2=insist
  left=10.10.10.1
  leftid=10.10.10.1
  leftsubnet=172.16.1.1/32
  right=10.10.10.2
  rightid=10.10.10.2
  rightsubnet=172.16.1.2/32
  authby=secret
  ike=aes256-sha256-modp2048
  esp=aes256-sha256
  pfs=yes
  ikelifetime=8h
  salifetime=1h
  dpddelay=30
  dpdtimeout=120
  dpdaction=restart
  auto=start
# server2
nano /etc/ipsec.d/section6-lab1.conf
conn s6-lab1
  type=tunnel
  ikev2=insist
  left=10.10.10.2
  leftid=10.10.10.2
  leftsubnet=172.16.1.2/32
  right=10.10.10.1
  rightid=10.10.10.1
  rightsubnet=172.16.1.1/32
  authby=secret
  ike=aes256-sha256-modp2048
  esp=aes256-sha256
  pfs=yes
  ikelifetime=8h
  salifetime=1h
  dpddelay=30
  dpdtimeout=120
  dpdaction=restart
  auto=start
# PSK on both servers
sudo tee /etc/ipsec.secrets >/dev/null <<'CONF'
10.10.10.1 10.10.10.2 : PSK "supersecret"
CONF
sudo chmod 600 /etc/ipsec.secrets
# restart & verify
sudo systemctl enable ipsec.service
sudo systemctl restart ipsec.service
sudo systemctl status ipsec.service
ipsec status
sudo ss -lun | grep -E ':500|:4500' || echo "IKE ports not listening"
ping -c2 172.16.1.2
# xfrm counters/policies
sudo ip -s xfrm state
sudo ip xfrm policy
# additional troubleshooting
sudo systemctl enable --now ipsec
sudo systemctl status ipsec
journalctl -u ipsec -b --no-pager
ipsec whack --status
ipsec verify
sudo ipsec addconn --checkconfig
sudo ipsec rereadsecrets
sudo systemctl restart ipsec
sudo ipsec status
EOS
}

# --- Lab list ---
print_list(){
  cat <<'EOF'
Section 6 Labs — IPsec/StrongSwan/WireGuard Tunnels
1. Scenario One
2. Troubleshooting 1 (Libreswan)            # was Lab 3
3. Troubleshooting 2 (Libreswan)            # was Lab 4
4. Troubleshooting 3 (Libreswan)            # was Lab 5
5. Scenario Six (StrongSwan PSK)            # was Lab 6
6. Scenario Seven (StrongSwan RSA/cert)     # was Lab 7
7. Troubleshooting 4 (StrongSwan)           # was Lab 8
8. Troubleshooting 5 (StrongSwan)           # was Lab 9
9. Troubleshooting 6 (StrongSwan)           # was Lab 10
10. Scenario Ten (WireGuard + IPsec)        # was Lab 11
11. Troubleshooting 7 (WireGuard + IPsec)   # was Lab 12
Usage:
  sudo section6-labs.sh <lab#> apply
  sudo section6-labs.sh <lab#> check
  sudo section6-labs.sh reset
  sudo section6-labs.sh status
  sudo section6-labs.sh list
  sudo section6-labs.sh solutions <lab#>
  sudo section6-labs.sh menu # interactive menu
EOF
}

# ============================================================
# APPLY (config vs troubleshooting)
# ============================================================

# --- Lab 1: Libreswan PSK (no changes applied) ---
lab1_apply(){
  echo "Lab 1 (Config): Review steps below (no changes applied)."
  print_netplan_yaml_server1
  print_netplan_yaml_server2
  cat <<EOF
- Build a site-to-site IPsec tunnel with IKEv2 PSK, AES-256/SHA-256, DH modp2048 (PFS).
- Protect ${S1_Dummy}/32 -> ${S2_Dummy}/32 via ${IFACE} (${S1_IF} -> ${S2_IF}).
- Allow UDP/500 & UDP/4500; ensure DPD restart and auto=start.
EOF
}

# --- Lab 2: Libreswan Troubleshooting (former Lab 3) ---
lab2_apply(){
  echo "Lab 2 (Troubleshooting): applying wrong tunnel identity + weak proposals."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab2
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_Dummy}/32
  right=${S2_IF}
  rightid=10.1.2.2   # WRONG: tunnel ID
  rightsubnet=${S2_Dummy}/32
  authby=secret
  ike=aes128-sha2_256-modp1024!  # WRONG/weak
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

# --- Lab 3: Libreswan Troubleshooting (former Lab 4) ---
lab3_apply(){
  echo "Lab 3 (Troubleshooting): applying RSA auth without certs + blocking IKE ports."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab3
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_Dummy}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_Dummy}/32
  authby=rsasig   # WRONG: RSA without certs
  ike=aes256-sha2_256-modp2048!
  esp=aes256-sha2_256!
  pfs=yes
  auto=start
EOF
  write_file "$LIBRE_SECRETS" 0600 <<'EOF'
# Intentionally incompatible with rsasig
EOF
  enable_service "$LIBRE_UNIT"
  ufw_block_ipsec
  echo -e "${OK} Deployed mismatched auth and blocked UDP/500/4500."
}

# --- Lab 4: Libreswan Troubleshooting (former Lab 5) ---
lab4_apply(){
  echo "Lab 4 (Troubleshooting): applying multiple faults + blocking IKE ports."
  ensure_libreswan
  write_file "$LIBRE_CONN" 0644 <<EOF
conn s6-lab4
  type=tunnel
  keyexchange=ikev2
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=172.16.9.1/32   # WRONG loopback
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=172.16.9.2/32  # WRONG loopback
  authby=rsasig              # WRONG auth (no certs)
  ike=aes128-sha1-modp1024!  # WRONG/legacy
  esp=3des-sha1!             # WRONG/legacy
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

# --- Lab 5: StrongSwan PSK (former Lab 6; no changes applied) ---
lab5_apply(){
  echo "Lab 5 (Config): Review steps below (no changes applied)."
  print_netplan_yaml_server1
  print_netplan_yaml_server2
  cat <<EOF
- Site-to-site StrongSwan with IKEv2 PSK, AES-256/SHA-256, DH modp2048 (PFS).
- Protect ${S1_Dummy}/32 -> ${S2_Dummy}/32 via ${IFACE} (${S1_IF} -> ${S2_IF}).
- Open UDP/500 & UDP/4500; auto=start.
EOF
}

# --- Lab 6: StrongSwan RSA/cert (former Lab 7; no changes applied) ---
lab6_apply(){
  echo "Lab 6 (Config): Review steps below (no changes applied)."
  print_netplan_yaml_server1
  print_netplan_yaml_server2
  cat <<'EOF'
- Site-to-site StrongSwan with IKEv2 RSA/cert authentication.
- AES-256/SHA-256, DH modp2048 (PFS), protect server loopbacks as specified.
- Generate CA + host certs (ipsec pki); place in /etc/ipsec.d/{cacerts,certs,private};
  set authby=rsasig and leftcert/rightcert.
EOF
}

# --- Lab 7: StrongSwan Troubleshooting (former Lab 8) ---
lab7_apply(){
  echo "Lab 7 (Troubleshooting StrongSwan): applying RSA auth without certs + weak proposals."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"
conn s6-lab7
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_Dummy}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_Dummy}/32
  authby=rsasig   # WRONG auth (no certs)
  ike=aes128-sha1-modp1024!  # WRONG/weak
  esp=aes128-sha1!           # WRONG
  auto=start
EOF
  write_file "$STRONG_SECRETS" 0600 <<'EOF'
# Empty; RSA selected with no certs to force mismatch
EOF
  enable_service "$STRONG_UNIT"
  ufw_allow_ipsec
  echo -e "${OK} StrongSwan with mismatched auth/crypto deployed."
}

# --- Lab 8: StrongSwan Troubleshooting (former Lab 9) ---
lab8_apply(){
  echo "Lab 8 (Troubleshooting StrongSwan): applying wrong loopbacks + wrong IDs."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"
conn s6-lab8
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=10.1.2.1     # WRONG ID
  leftsubnet=172.16.9.1/32 # WRONG loopback
  right=${S2_IF}
  rightid=10.1.2.2    # WRONG ID
  rightsubnet=172.16.9.2/32 # WRONG loopback
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

# --- Lab 9: StrongSwan Troubleshooting (former Lab 10) ---
lab9_apply(){
  echo "Lab 9 (Troubleshooting StrongSwan): applying weak proposals + blocking ICMP."
  ensure_strongswan
  write_file "$STRONG_MAIN" 0644 <<EOF
config setup
  charondebug="ike 1, knl 1, cfg 0"
conn s6-lab9
  keyexchange=ikev2
  type=tunnel
  left=${S1_IF}
  leftid=${S1_IF}
  leftsubnet=${S1_Dummy}/32
  right=${S2_IF}
  rightid=${S2_IF}
  rightsubnet=${S2_Dummy}/32
  authby=secret
  ike=aes128-sha1-modp1024!  # WRONG/weak
  esp=aes128-sha1!           # WRONG
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

# --- Lab 10: WireGuard + IPsec transport (former Lab 11; Config, no changes applied) ---
lab10_apply(){
  echo "Lab 10 (Config): WireGuard tunnel with IPsec transport (no changes applied)."
  print_netplan_yaml_server1
  print_netplan_yaml_server2
  cat <<EOF
- Build a WireGuard tunnel between Server1 and Server2 (${S1_IF} <-> ${S2_IF}).
- WireGuard interface: wg0, addresses 192.168.100.1/24 (Server1), 192.168.100.2/24 (Server2).
- Protect WireGuard traffic with IPsec in transport mode (ESP). Use StrongSwan PSK: AES-256/SHA-256, modp2048.
- Allow UDP/51820 (WireGuard) and UDP/500/4500 (IPsec).
- Ensure ping -I wg0 192.168.100.2 works from 192.168.100.1.
EOF
}

# --- Lab 11: WireGuard + IPsec transport (former Lab 12; Troubleshooting) ---
lab11_apply(){
  echo "Lab 11 (Troubleshooting): Broken WireGuard + IPsec config (wrong peer key, wrong PSK, UDP/51820 blocked)."
  q apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard strongswan ufw
  # Generate Server1 WireGuard keys
  mkdir -p /etc/wireguard/keys
  chmod 700 /etc/wireguard/keys
  if ! has_cmd wg; then
    echo -e "${FAIL} WireGuard tool 'wg' not found after install."; exit 3
  fi
  S1_PRIV=$(wg genkey)
  S1_PUB=$(echo "$S1_PRIV" | wg pubkey)
  echo "$S1_PRIV" >/etc/wireguard/keys/server1_private.key
  echo "$S1_PUB"  >/etc/wireguard/keys/server1_public.key
  chmod 600 /etc/wireguard/keys/server1_private.key
  chmod 644 /etc/wireguard/keys/server1_public.key
  # Broken WireGuard config: local key OK, peer key WRONG
  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 192.168.100.1/24
PrivateKey = ${S1_PRIV}
ListenPort = 51820
[Peer]
PublicKey = <WRONG_peer_public_key>
Endpoint = ${S2_IF}:51820
AllowedIPs = 192.168.100.2/32
EOF
  # Broken IPsec transport config: wrong PSK
  cat > /etc/ipsec.conf <<EOF
config setup
conn wg-ipsec
  keyexchange=ikev2
  type=transport
  left=${S1_IF}
  right=${S2_IF}
  authby=secret
  ike=aes256-sha256-modp2048
  esp=aes256-sha256
  auto=start
EOF
  cat > /etc/ipsec.secrets <<EOF
${S1_IF} ${S2_IF} : PSK "WRONGsecret"
EOF
  chmod 600 /etc/ipsec.secrets
  # Block UDP/51820 (WireGuard)
  q ufw --force enable
  ufw deny 51820/udp || true
  # Do not start wg0 automatically—leave it for students
  enable_service "$STRONG_UNIT"
  echo -e "${OK} Broken WG+IPsec applied (local keys generated, wrong peer key, wrong PSK, UDP/51820 denied)."
}

apply_lab(){
  local lab="$1"
  case "$lab" in
    1)  lab1_apply ;;
    2)  lab2_apply ;;
    3)  lab3_apply ;;
    4)  lab4_apply ;;
    5)  lab5_apply ;;
    6)  lab6_apply ;;
    7)  lab7_apply ;;
    8)  lab8_apply ;;
    9)  lab9_apply ;;
    10) lab10_apply ;;
    11) lab11_apply ;;
    *)  echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
  save_state lab "$lab"
  echo -e "${OK} Applied Lab $lab"
}

# ============================================================
# CHECKS
# ============================================================
can_ping(){ ping -c1 -W1 "$1" >/dev/null 2>&1; }

lab1_check(){
  begin_check
  can_ping "$S2_Dummy" && good "peer loopback (${S2_Dummy}) reachable" || miss "Cannot ping peer loopback"
  can_ping "$S1_Dummy" && good "local loopback (${S1_Dummy}) reachable" || miss "Cannot ping local loopback"
  if has_cmd ss; then
    ss -lun | grep -q ':500'  && good "UDP/500 listening"  || miss "UDP/500 not listening"
    ss -lun | grep -q ':4500' && good "UDP/4500 listening" || miss "UDP/4500 not listening"
  else
    good "Skipping port check (ss not available)"
  fi
  end_check
}

# Lab 2 checks (former Lab 3)
lab2_check(){
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

# Lab 3 checks (former Lab 4)
lab3_check(){
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

# Lab 4 checks (former Lab 5)
lab4_check(){
  begin_check
  if [[ -f "$LIBRE_CONN" ]]; then
    grep -q 'leftsubnet=172.16.9.1/32' "$LIBRE_CONN"  && miss "Wrong left loopback — ${S1_Dummy}/32 required" || good "Left loopback looks OK"
    grep -q 'rightsubnet=172.16.9.2/32' "$LIBRE_CONN" && miss "Wrong right loopback — ${S2_Dummy}/32 required" || good "Right loopback looks OK"
    grep -q 'ike=aes128' "$LIBRE_CONN"                   && miss "Weak IKE proposal" || good "IKE proposal looks OK"
    grep -q 'esp=3des' "$LIBRE_CONN"                     && miss "Legacy ESP cipher (3DES)" || good "ESP cipher looks OK"
    grep -q 'authby=rsasig' "$LIBRE_CONN"                && miss "Auth mismatch (RSA w/o certs)" || good "Auth method looks OK"
  else
    miss "No ${LIBRE_CONN} found"
  fi
  if has_cmd ufw; then
    ufw status | grep -E '500/udp.*DENY|4500/udp.*DENY' >/dev/null && miss "UFW denies UDP/500 or 4500" || good "UFW not denying IKE ports"
  fi
  end_check
}

# Lab 5 checks (former Lab 6)
lab5_check(){
  begin_check
  can_ping "$S2_Dummy" && good "peer loopback (${S2_Dummy}) reachable" || miss "Cannot ping peer loopback"
  if has_cmd ss; then
    ss -lun | grep -q ':500'  && good "UDP/500 listening"  || miss "UDP/500 not listening"
    ss -lun | grep -q ':4500' && good "UDP/4500 listening" || miss "UDP/4500 not listening"
  else
    good "Skipping port check (ss not available)"
  fi
  end_check
}

# Lab 6 checks (former Lab 7)
lab6_check(){
  begin_check
  can_ping "$S2_Dummy" && good "peer loopback (${S2_Dummy}) reachable" || miss "Cannot ping peer loopback"
  end_check
}

# Lab 7 checks (former Lab 8)
lab7_check(){
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'authby=rsasig' "$STRONG_MAIN" && miss "RSA selected without certs — fix to PSK or configure certs" || good "Auth not mismatched"
    grep -q 'ike=aes128' "$STRONG_MAIN"    && miss "StrongSwan IKE uses AES-128; fix to AES-256 + modp2048" || good "IKE proposal looks OK"
    grep -q 'esp=aes128' "$STRONG_MAIN"    && miss "StrongSwan ESP uses AES-128; fix to AES-256" || good "ESP proposal looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  end_check
}

# Lab 8 checks (former Lab 9)
lab8_check(){
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'leftid=10.1.2.1'     "$STRONG_MAIN" && miss "Wrong left ID — use ${S1_IF} or proper identity" || good "Left ID looks OK"
    grep -q 'rightid=10.1.2.2'    "$STRONG_MAIN" && miss "Wrong right ID — use ${S2_IF}" || good "Right ID looks OK"
    grep -q 'leftsubnet=172.16.9.1/32'  "$STRONG_MAIN" && miss "Wrong left loopback — ${S1_Dummy}/32 required" || good "Left loopback looks OK"
    grep -q 'rightsubnet=172.16.9.2/32' "$STRONG_MAIN" && miss "Wrong right loopback — ${S2_Dummy}/32 required" || good "Right loopback looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  end_check
}

# Lab 9 checks (former Lab 10)
lab9_check(){
  begin_check
  if [[ -f "$STRONG_MAIN" ]]; then
    grep -q 'ike=aes128' "$STRONG_MAIN" && miss "StrongSwan IKE uses AES-128; fix to AES-256 + modp2048" || good "IKE proposal looks OK"
    grep -q 'esp=aes128' "$STRONG_MAIN" && miss "StrongSwan ESP uses AES-128; fix to AES-256" || good "ESP proposal looks OK"
  else
    miss "No ${STRONG_MAIN} found"
  fi
  if can_ping "$S2_Dummy"; then
    good "ICMP not blocked; loopback ping works"
  else
    miss "ICMP likely blocked; allow ICMP to pass"
  fi
  end_check
}

# Lab 10 check (WireGuard + IPsec; former Lab 11)
lab10_check(){
  begin_check
  ip link show wg0 >/dev/null 2>&1 && good "wg0 interface exists" || miss "wg0 interface missing"
  ip addr show wg0 2>/dev/null | grep -q '192.168.100.1' && good "wg0 has correct IP (192.168.100.1/24)" || miss "wg0 IP missing"
  ip xfrm state | grep -q "src ${S1_IF} dst ${S2_IF}" && good "IPsec transport SA present" || miss "IPsec transport SA missing"
  has_cmd ss && ss -lun | grep -q ':51820' && good "UDP/51820 listening" || miss "UDP/51820 not listening"
  ping -c1 -I wg0 192.168.100.2 >/dev/null 2>&1 && good "Ping over wg0 works" || miss "Ping over wg0 fails"
  end_check
}

# Lab 11 check (WireGuard + IPsec troubleshooting; former Lab 12)
lab11_check(){
  begin_check
  grep -q 'WRONGsecret' /etc/ipsec.secrets && miss "Wrong IPsec PSK (should be correct shared secret)" || good "IPsec PSK looks OK"
  if has_cmd ufw; then
    ufw status | grep -q '51820/udp.*DENY' && miss "UFW denies UDP/51820" || good "UFW allows UDP/51820"
  else
    good "UFW not installed — skipping 51820 DENY check"
  fi
  grep -q '\<WRONG_peer_public_key\>' /etc/wireguard/wg0.conf && miss "Wrong WireGuard peer public key in wg0.conf" || good "WireGuard peer key looks OK"
  end_check
}

do_check(){
  local lab="$1"
  case "$lab" in
    1)  lab1_check ;;
    2)  lab2_check ;;
    3)  lab3_check ;;
    4)  lab4_check ;;
    5)  lab5_check ;;
    6)  lab6_check ;;
    7)  lab7_check ;;
    8)  lab8_check ;;
    9)  lab9_check ;;
    10) lab10_check ;;
    11) lab11_check ;;
    *)  echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# ============================================================
# SOLUTIONS (full steps & commands; include YAML)
# ============================================================
print_solution(){
  local lab="$1"
  echo "------ Solutions for Lab ${lab} ------"
  case "$lab" in
    1) print_solution_block ;;
    2) print_solution_block ;;  # troubleshooting guidance is covered by baseline + fix-ups in checks
    3) print_solution_block ;;
    4) print_solution_block ;;
    5) print_solution_block ;;
    6) print_solution_block ;;
    7) print_solution_block ;;
    8) print_solution_block ;;
    9) print_solution_block ;;
    10)
      cat <<'EOS'
# WireGuard + IPsec Transport — Scenario
# WireGuard on both servers; IPsec transport protecting WG traffic.
# Server1 /etc/wireguard/wg0.conf
[Interface]
Address = 192.168.100.1/24
PrivateKey = <server1_private_key_contents>
ListenPort = 51820
[Peer]
PublicKey = <server2_public_key_contents>
Endpoint = 10.10.10.2:51820
AllowedIPs = 192.168.100.2/32
# Server2 /etc/wireguard/wg0.conf
[Interface]
Address = 192.168.100.2/24
PrivateKey = <server2_private_key_contents>
ListenPort = 51820
[Peer]
PublicKey = <server1_public_key_contents>
Endpoint = 10.10.10.1:51820
AllowedIPs = 192.168.100.1/32
# Generate keys (each server)
umask 077
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
# Start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
# IPsec transport (StrongSwan) on both servers:
/etc/ipsec.conf
config setup
conn wg-ipsec
  keyexchange=ikev2
  type=transport
  left=10.10.10.1
  right=10.10.10.2
  authby=secret
  ike=aes256-sha256-modp2048
  esp=aes256-sha256
  auto=start
# Shared secret
/etc/ipsec.secrets
10.10.10.1 10.10.10.2 : PSK "supersecret"
sudo systemctl enable strongswan-starter
sudo systemctl restart strongswan-starter
# Allow UDP/51820, 500, 4500
sudo ufw allow 51820/udp
sudo ufw allow 500/udp
sudo ufw allow 4500/udp
# Test ping over wg0
ping -c2 -I wg0 192.168.100.2
EOS
      ;;
    11)
      cat <<'EOS'
# Troubleshooting — WireGuard + IPsec transport
# Fix sequence:
# 1) Correct WireGuard peer public key in /etc/wireguard/wg0.conf
#    Replace <WRONG_peer_public_key> with the actual peer public key.
# 2) Unblock UDP/51820 in UFW:
sudo ufw delete deny 51820/udp
sudo ufw allow 51820/udp
# 3) Fix IPsec PSK in /etc/ipsec.secrets to match both sides:
10.10.10.1 10.10.10.2 : PSK "supersecret"
sudo chmod 600 /etc/ipsec.secrets
sudo systemctl restart strongswan-starter
# 4) Bring up WireGuard:
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
# 5) Validate:
ss -lun | grep -E ':51820|:500|:4500'
wg show
ip xfrm state
ping -c2 -I wg0 192.168.100.2
EOS
      ;;
    *) echo -e "${FAIL} Unknown lab ${lab}" ;;
  esac
  echo "--------------------------------------"
}

# ============================================================
# RESET / STATUS
# ============================================================
reset_all(){
  disable_service "$LIBRE_UNIT"
  disable_service "$STRONG_UNIT"
  if has_cmd ufw; then
    ufw delete deny 500/udp 2>/dev/null || true
    ufw delete deny 4500/udp 2>/dev/null || true
    ufw delete deny 51820/udp 2>/dev/null || true
  fi
  unblock_icmp
  rm -f "$LIBRE_CONN" "$STRONG_MAIN" "$STRONG_SECRETS" "$LIBRE_SECRETS" \
        /etc/wireguard/wg0.conf /etc/wireguard/keys/server1_private.key /etc/wireguard/keys/server1_public.key
  : > "$STATE_FILE" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}
status(){
  local lab; lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Libreswan unit: ${LIBRE_UNIT} — $(systemctl is-active "${LIBRE_UNIT}" 2>/dev/null || echo inactive)"
  echo -e "${INFO} StrongSwan unit: ${STRONG_UNIT} — $(systemctl is-active "${STRONG_UNIT}" 2>/dev/null || echo inactive)"
  echo -e "${INFO} Libreswan conn file: ${LIBRE_CONN} $([[ -f "${LIBRE_CONN}" ]] && echo '[present]' || echo '[missing]')"
  echo -e "${INFO} StrongSwan conf: ${STRONG_MAIN} $([[ -f "${STRONG_MAIN}" ]] && echo '[present]' || echo '[missing]')"
  if has_cmd ufw; then
    echo -e "${INFO} UFW status:"; ufw status || true
  else
    echo -e "${INFO} UFW not installed."
  fi
  echo -e "${INFO} Loopback addresses:"; ip addr show lo | sed -n 's/^\s*inet\s\([0-9./]*\).*/\1/p'
  echo -e "${INFO} Interface ${IFACE} IP:"; iface_ip "${IFACE}" || true
  [[ -f /etc/wireguard/wg0.conf ]] && echo -e "${INFO} WireGuard conf present: /etc/wireguard/wg0.conf"
}

# ============================================================
# INTERACTIVE MENU
# ============================================================
interactive_menu(){
  while true; do
    clear
    echo "=== Section 6 Labs Menu (IPsec / StrongSwan / WireGuard) ==="
    echo "1) Apply Lab"
    echo "2) Check Lab"
    echo "3) Reset"
    echo "4) Status"
    echo "5) List Labs"
    echo "6) Solutions"
    echo "q) Quit"
    read -rp "Select option: " opt
    case "$opt" in
      1)  read -rp "Lab (1-11): " lab; apply_lab "$lab"; read -rp "Press Enter..." ;;
      2)  read -rp "Lab (1-11): " lab; do_check "$lab"; read -rp "Press Enter..." ;;
      3)  reset_all; read -rp "Press Enter..." ;;
      4)  status; read -rp "Press Enter..." ;;
      5)  print_list; read -rp "Press Enter..." ;;
      6)  read -rp "Lab (1-11): " lab; print_solution "$lab"; read -rp "Press Enter..." ;;
      q|Q) exit 0 ;;
      *)  echo "Invalid selection"; sleep 1 ;;
    esac
  done
}

# ============================================================
# MAIN
# ============================================================
main(){
  mkdirs
  if [[ $# -lt 1 ]]; then
    interactive_menu
    exit 0
  fi
  case "$1" in
    menu)      interactive_menu; exit 0 ;;
    list)      print_list; exit 0 ;;
    status)    status; exit 0 ;;
    reset)     reset_all; exit 0 ;;
    solutions) [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }
               print_solution "$2"; exit 0 ;;
  esac
  local lab="$1"
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 <lab#> apply|check"; exit 2; }
  case "$2" in
    apply) apply_lab "$lab" ;;
    check) do_check "$lab" ;;
    *)     echo -e "${FAIL} Use: apply|check"; exit 2 ;;
  esac
}
