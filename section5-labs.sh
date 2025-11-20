**Keeping the code concise**

Okay, I definitely don’t want to make this too long, but I still need to include all the necessary code. It’s one of those balancing acts where short and sweet doesn’t always work when it’s technical. I’ll focus on ensuring that I include everything crucial but keep the explanations and extras to a minimum. I think it's best to make sure that the code is functional and complete, but I’ll avoid unnecessary complexity.
### Complete script for section 5 openvpn labs

```bash
#!/usr/bin/env bash
# Section 5 - SSL VPN (OpenVPN) Labs
# Labs:
# 1) Configure OpenVPN for SSL VPN (server on ens4 + loopback 1.1.1.1 reachable via VPN)
# 2) Troubleshoot OpenVPN — Wrong IP in routing (bad: push route 1.1.1.2; fix to 1.1.1.1)
# 3) Troubleshoot OpenVPN — No network configured for remote users (missing 'server' directive)
# 4) Troubleshoot OpenVPN — Only listening on ens3 instead of ens4 (bad local bind)
# 5) Troubleshoot OpenVPN — Wrong loopback IP (bad: 2.2.2.2 instead of 1.1.1.1)
# 6) Troubleshoot OpenVPN — Firewall blocking UDP/1194 (UFW denies; open UDP/1194)

# ---- Run-as-root check BEFORE strict mode/trap ----
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

# ===== Paths / constants =====
LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"

# OpenVPN paths
OPENVPN_DIR="/etc/openvpn"
OPENVPN_CONF="${OPENVPN_DIR}/server.conf"
OPENVPN_STATUS="/var/log/openvpn-status.log"
EASYRSA_DIR="/usr/share/easy-rsa"
PKI_DIR="${OPENVPN_DIR}/pki"

# Network constants
IFACE="ens4"
ALT_IFACE="ens3"            # used to simulate wrong bind in lab4
LO_GOOD_IP="1.1.1.1"
LO_BAD_IP="2.2.2.2"
VPN_NET="10.8.0.0"
VPN_MASK="255.255.255.0"

# Colors/icons
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"

# Helpers
q(){ "$@" >/dev/null 2>&1 || true; }
mkdirs(){ mkdir -p "$LAB_ROOT"; }
save_state(){ local k="$1" v="$2"; mkdirs; touch "$STATE_FILE"; grep -q "^${k}=" "$STATE_FILE" && sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE" || echo "${k}=${v}" >>"$STATE_FILE"; }
get_state(){ local k="$1"; [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }; grep "^${k}=" "$STATE_FILE" | tail -n1 | cut -d= -f2- || true; }
good(){ echo -e "${OK} $*"; }
miss(){ echo -e "${FAIL} $*"; FAILS=$((FAILS+1)); }
begin_check(){ FAILS=0; }
end_check(){ if [[ ${FAILS:-0} -eq 0 ]]; then echo -e "${OK} All checks passed"; else echo -e "${FAIL} ${FAILS} issue(s) found"; exit 4; fi; }

write_file(){ # write_file <path> <mode> ; content from stdin
  local path="$1" mode="$2"
  umask 022
  cat >"$path"
  chmod "$mode" "$path" || true
  chown root:root "$path" || true
}

iface_ip(){
  ip -4 addr show "$1" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

ensure_packages(){
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openvpn easy-rsa iproute2 ufw
}

ensure_loopback_good(){
  ip addr add "${LO_GOOD_IP}/32" dev lo 2>/dev/null || true
}

ensure_loopback_bad(){
  ip addr add "${LO_BAD_IP}/32" dev lo 2>/dev/null || true
}

remove_loopbacks(){
  ip addr del "${LO_GOOD_IP}/32" dev lo 2>/dev/null || true
  ip addr del "${LO_BAD_IP}/32" dev lo 2>/dev/null || true
}

ensure_pki(){
  # Initialize a minimal TLS PKI via easy-rsa (no passphrases) for server to start cleanly
  mkdir -p "$PKI_DIR"
  if [[ ! -d "${PKI_DIR}/easyrsa" ]]; then
    cp -r "$EASYRSA_DIR" "${PKI_DIR}/easyrsa"
  fi
  pushd "${PKI_DIR}/easyrsa" >/dev/null
    ./easyrsa init-pki
    yes "" | ./easyrsa build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass
    openvpn --genkey --secret "${PKI_DIR}/ta.key"
  popd >/dev/null

  # Place certs/keys in OpenVPN dir expected names
  ln -sf "${PKI_DIR}/easyrsa/pki/ca.crt"           "${OPENVPN_DIR}/ca.crt"
  ln -sf "${PKI_DIR}/easyrsa/pki/issued/server.crt" "${OPENVPN_DIR}/server.crt"
  ln -sf "${PKI_DIR}/easyrsa/pki/private/server.key" "${OPENVPN_DIR}/server.key"
  ln -sf "${PKI_DIR}/easyrsa/pki/dh.pem"            "${OPENVPN_DIR}/dh.pem"
  ln -sf "${PKI_DIR}/ta.key"                        "${OPENVPN_DIR}/ta.key"
}

enable_openvpn(){
  # Use systemd instance service openvpn@server
  q systemctl enable openvpn@server
  q systemctl restart openvpn@server
}

disable_openvpn(){
  q systemctl stop openvpn@server
  q systemctl disable openvpn@server
}

ufw_block_1194(){
  q ufw --force enable
  ufw deny 1194/udp || true
}

ufw_allow_1194(){
  q ufw --force enable
  ufw delete deny 1194/udp 2>/dev/null || true
  ufw allow 1194/udp || true
}

summary_for_lab(){
  local lab="$1"
  case "$lab" in
    1) cat <<EOF
${BOLD}Lab 1 — Configure OpenVPN for SSL VPN${NC}
- OpenVPN server bound to ens4 with VPN subnet ${VPN_NET}/${VPN_MASK}
- Push host route to loopback ${LO_GOOD_IP} so remote users can ping it
EOF
    ;;
    2) cat <<EOF
${BOLD}Lab 2 — Troubleshoot Wrong IP in Routing${NC}
- Misconfigured push route to ${LO_BAD_IP}; fix to ${LO_GOOD_IP}
EOF
    ;;
    3) cat <<EOF
${BOLD}Lab 3 — Troubleshoot No Network for Remote Users${NC}
- Missing 'server ${VPN_NET} ${VPN_MASK}' directive; add it
EOF
    ;;
    4) cat <<EOF
${BOLD}Lab 4 — Troubleshoot Listening Interface${NC}
- Server bound to ${ALT_IFACE} (wrong). Ensure it binds to ${IFACE}
EOF
    ;;
    5) cat <<EOF
${BOLD}Lab 5 — Troubleshoot Wrong Loopback IP${NC}
- Host loopback set to ${LO_BAD_IP}; should be ${LO_GOOD_IP}
EOF
    ;;
    6) cat <<EOF
${BOLD}Lab 6 — Troubleshoot Firewall Blocking UDP/1194${NC}
- UFW blocks UDP/1194; open the port to allow VPN
EOF
    ;;
    *) echo -e "${FAIL} Unknown lab $lab" ;;
  esac
}

# =========================
# APPLY FUNCTIONS (create target state for each lab)
# =========================
lab1_apply(){
  ensure_packages
  ensure_pki
  ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"

  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${local_ip}
server ${VPN_NET} ${VPN_MASK}
push "route ${LO_GOOD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

# TLS
ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  enable_openvpn
}

lab2_apply(){
  ensure_packages
  ensure_pki
  ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"

  # Create a misconfigured route (wrong IP 2.2.2.2)
  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${local_ip}
server ${VPN_NET} ${VPN_MASK}
push "route ${LO_BAD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  enable_openvpn
}

lab3_apply(){
  ensure_packages
  ensure_pki
  ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"

  # Missing 'server' directive entirely
  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${local_ip}
# server directive intentionally missing
push "route ${LO_GOOD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  enable_openvpn
}

lab4_apply(){
  ensure_packages
  ensure_pki
  ensure_loopback_good
  alt_ip="$(iface_ip "$ALT_IFACE")"
  if [[ -z "$alt_ip" ]]; then
    # Simulate wrong bind by setting an invalid local IP
    alt_ip="0.0.0.0"
  fi

  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${alt_ip}   # WRONG: bound to ${ALT_IFACE} or invalid
server ${VPN_NET} ${VPN_MASK}
push "route ${LO_GOOD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  enable_openvpn
}

lab5_apply(){
  ensure_packages
  ensure_pki
  remove_loopbacks
  ensure_loopback_bad
  local_ip="$(iface_ip "$IFACE")"

  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${local_ip}
server ${VPN_NET} ${VPN_MASK}
push "route ${LO_GOOD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  enable_openvpn
}

lab6_apply(){
  ensure_packages
  ensure_pki
  ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"

  write_file "$OPENVPN_CONF" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${local_ip}
server ${VPN_NET} ${VPN_MASK}
push "route ${LO_GOOD_IP} 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status ${OPENVPN_STATUS}
verb 3

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
EOF

  ufw_block_1194
  enable_openvpn
}

# =========================
# CHECK FUNCTIONS
# =========================
lab1_check(){
  begin_check
  systemctl is-active --quiet openvpn@server && good "OpenVPN server is running" || miss "OpenVPN server not running"
  grep -q "^server ${VPN_NET} ${VPN_MASK}" "$OPENVPN_CONF" && good "VPN subnet configured" || miss "VPN subnet missing"
  grep -q "push \"route ${LO_GOOD_IP} 255.255.255.255\"" "$OPENVPN_CONF" && good "Route to ${LO_GOOD_IP} pushed" || miss "Route to ${LO_GOOD_IP} not pushed"
  ip addr show lo | grep -q "${LO_GOOD_IP}" && good "Loopback ${LO_GOOD_IP} present" || miss "Loopback ${LO_GOOD_IP} missing"
  ss -lun | grep -q ":1194" && good "UDP/1194 is listening" || miss "UDP/1194 is not listening"
  end_check
}

lab2_check(){
  begin_check
  grep -q "push \"route ${LO_BAD_IP} 255.255.255.255\"" "$OPENVPN_CONF" && good "Detected wrong route ${LO_BAD_IP}" || miss "Wrong route not found"
  grep -q "push \"route ${LO_GOOD_IP} 255.255.255.255\"" "$OPENVPN_CONF" || good "Expected fix: change to ${LO_GOOD_IP}"
  end_check
}

lab3_check(){
  begin_check
  if grep -q "^server " "$OPENVPN_CONF"; then
    miss "Server directive present (should be missing for this lab's fault)"
  else
    good "Server directive missing (fault replicated)"
  fi
  end_check
}

lab4_check(){
  begin_check
  bound_ip="$(awk '/^local /{print $2}' "$OPENVPN_CONF" | head -n1 || true)"
  if [[ -z "$bound_ip" ]]; then
    miss "No local bind configured"
  else
    good "Local bind configured: ${bound_ip}"
  fi
  correct_ip="$(iface_ip "$IFACE")"
  [[ "$bound_ip" == "$correct_ip" ]] && miss "Bound to ens4 already (fault should be ens3/invalid)" || good "Not bound to ens4 (fault replicated)"
  end_check
}

lab5_check(){
  begin_check
  ip addr show lo | grep -q "${LO_BAD_IP}" && good "Detected wrong loopback ${LO_BAD_IP}" || miss "Wrong loopback ${LO_BAD_IP} not present"
  ip addr show lo | grep -q "${LO_GOOD_IP}" && miss "Found ${LO_GOOD_IP} (should be wrong for this lab)" || good "Correct fault state (no ${LO_GOOD_IP})"
  end_check
}

lab6_check(){
  begin_check
  # Check if UDP/1194 appears blocked by UFW
  ufw status | grep -q "1194/udp.*DENY" && good "UFW denies UDP/1194" || miss "UFW not denying UDP/1194"
  end_check
}

# =========================
# APPLY (with summaries)
# =========================
apply_lab(){
  local lab="$1"
  summary_for_lab "$lab"
  case "$lab" in
    1) lab1_apply ;;
    2) lab2_apply ;;
    3) lab3_apply ;;
    4) lab4_apply ;;
    5) lab5_apply ;;
    6) lab6_apply ;;
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
    4) lab4_check ;;
    5) lab5_check ;;
    6) lab6_check ;;
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# =========================
# RESET / STATUS / LIST
# =========================
reset_all(){
  disable_openvpn

  # Remove firewall rules
  ufw delete allow 1194/udp 2>/dev/null || true
  ufw delete deny 1194/udp 2>/dev/null || true

  # Remove configs/PKI
  rm -f "${OPENVPN_CONF}" "${OPENVPN_STATUS}"
  rm -rf "${PKI_DIR}"

  # Remove loopback IPs
  remove_loopbacks

  : > "${STATE_FILE}" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}

status(){
  local lab
  lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} OpenVPN status:"; systemctl status openvpn@server --no-pager || true
  echo -e "${INFO} UFW status:"; ufw status || true
  echo -e "${INFO} Loopback IPs:"; ip addr show lo | sed -n 's/^\s*inet\s\([0-9.\/]*\).*/\1/p'
  echo -e "${INFO} Interface ${IFACE} IP:"; iface_ip "$IFACE" || true
}

print_list(){
  cat <<EOF
${BOLD}Section 5 Labs — OpenVPN SSL VPN${NC}
1. Configure OpenVPN for SSL VPN (ens4 + 1.1.1.1 loopback)
2. Troubleshoot — Wrong IP in routing
3. Troubleshoot — No network configured for remote users
4. Troubleshoot — Only listening on ens3 instead of ens4
5. Troubleshoot — Wrong loopback IP
6. Troubleshoot — Firewall blocking UDP/1194

Usage:
  sudo $0 <lab#> apply
  sudo $0 <lab#> check
  sudo $0 reset
  sudo $0 status
  sudo $0 list
  sudo $0 solutions <lab#>
  sudo $0 tips <lab#>
EOF
}

# =========================
# SOLUTIONS (fully step-by-step with all commands & files)
# =========================
print_solution(){
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1) cat <<'EOS'
# Lab 1 — Configure OpenVPN for SSL VPN (ens4 + loopback 1.1.1.1)

## 1) Install packages
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa iproute2 ufw

## 2) Add loopback 1.1.1.1
sudo ip addr add 1.1.1.1/32 dev lo

## 3) Build minimal PKI with easy-rsa (no passphrases)
sudo mkdir -p /etc/openvpn/pki
sudo cp -r /usr/share/easy-rsa /etc/openvpn/pki/easyrsa
cd /etc/openvpn/pki/easyrsa
sudo ./easyrsa init-pki
yes "" | sudo ./easyrsa build-ca nopass
sudo ./easyrsa gen-dh
sudo ./easyrsa build-server-full server nopass
sudo openvpn --genkey --secret /etc/openvpn/pki/ta.key

## 4) Link certs/keys
sudo ln -sf /etc/openvpn/pki/easyrsa/pki/ca.crt            /etc/openvpn/ca.crt
sudo ln -sf /etc/openvpn/pki/easyrsa/pki/issued/server.crt /etc/openvpn/server.crt
sudo ln -sf /etc/openvpn/pki/easyrsa/pki/private/server.key /etc/openvpn/server.key
sudo ln -sf /etc/openvpn/pki/easyrsa/pki/dh.pem            /etc/openvpn/dh.pem
sudo ln -sf /etc/openvpn/pki/ta.key                        /etc/openvpn/ta.key

## 5) Create server.conf (bind to ens4, push 1.1.1.1 route)
ENS4_IP=$(ip -4 addr show ens4 | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
sudo tee /etc/openvpn/server.conf >/dev/null <<CONF
port 1194
proto udp
dev tun
user nobody
group nogroup
local ${ENS4_IP}
server 10.8.0.0 255.255.255.0
push "route 1.1.1.1 255.255.255.255"
topology subnet
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
tls-auth /etc/openvpn/ta.key 0
CONF

## 6) Start OpenVPN
sudo systemctl enable --now openvpn@server
sudo systemctl status openvpn@server --no-pager

## 7) Verify
ss -lun | grep ':1194' || echo "UDP/1194 not listening"
ip addr show lo | grep '1.1.1.1'
EOS
    ;;
    2) cat <<'EOS'
# Lab 2 — Troubleshoot Wrong IP in Routing (fix push route to 1.1.1.1)

## 1) Inspect existing route push
grep -n 'push "route' /etc/openvpn/server.conf

## 2) Fix wrong IP (2.2.2.2 -> 1.1.1.1)
sudo sed -i 's/push "route .*"/push "route 1.1.1.1 255.255.255.255"/' /etc/openvpn/server.conf

## 3) Ensure loopback exists
sudo ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true
sudo ip addr del 2.2.2.2/32 dev lo 2>/dev/null || true

## 4) Restart OpenVPN
sudo systemctl restart openvpn@server

## 5) Verify
grep 'push "route 1.1.1.1' /etc/openvpn/server.conf
ip addr show lo | grep '1.1.1.1'
EOS
    ;;
    3) cat <<'EOS'
# Lab 3 — Troubleshoot No Network for Remote Users (add server directive)

## 1) Check if 'server' directive is missing
grep -n '^server ' /etc/openvpn/server.conf || echo "server directive missing"

## 2) Add VPN subnet
echo 'server 10.8.0.0 255.255.255.0' | sudo tee -a /etc/openvpn/server.conf

## 3) Restart OpenVPN
sudo systemctl restart openvpn@server

## 4) Verify
grep '^server 10.8.0.0 255.255.255.0' /etc/openvpn/server.conf
sudo systemctl status openvpn@server --no-pager
EOS
    ;;
    4) cat <<'EOS'
# Lab 4 — Troubleshoot Listening Interface (bind to ens4 instead of ens3/invalid)

## 1) Show current local bind
grep -n '^local ' /etc/openvpn/server.conf

## 2) Set local to ens4 IP
ENS4_IP=$(ip -4 addr show ens4 | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
sudo sed -i "s/^local .*/local ${ENS4_IP}/" /etc/openvpn/server.conf

## 3) Restart OpenVPN
sudo systemctl restart openvpn@server

## 4) Verify bind
grep '^local ' /etc/openvpn/server.conf
ss -lun | grep ':1194' || echo "UDP/1194 not listening"
EOS
    ;;
    5) cat <<'EOS'
# Lab 5 — Troubleshoot Wrong Loopback IP (use 1.1.1.1)

## 1) Remove wrong loopback and add correct
sudo ip addr del 2.2.2.2/32 dev lo 2>/dev/null || true
sudo ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true

## 2) Ensure server pushes the correct route
sudo sed -i 's/push "route .*"/push "route 1.1.1.1 255.255.255.255"/' /etc/openvpn/server.conf

## 3) Restart OpenVPN
sudo systemctl restart openvpn@server

## 4) Verify
ip addr show lo | grep '1.1.1.1'
grep 'push "route 1.1.1.1' /etc/openvpn/server.conf
EOS
    ;;
    6) cat <<'EOS'
# Lab 6 — Troubleshoot Firewall Blocking UDP/1194 (open the port)

## 1) Check UFW status and rules
sudo ufw status

## 2) Allow UDP/1194
sudo ufw --force enable
sudo ufw allow 1194/udp

## 3) Restart OpenVPN (if needed)
sudo systemctl restart openvpn@server

## 4) Verify
sudo ufw status | grep '1194/udp'
ss -lun | grep ':1194' || echo "UDP/1194 not listening"
EOS
    ;;
    *) echo -e "${FAIL} Unknown lab $lab" ;;
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
  case "$lab" in
    1) echo "Use 'local <ens4-IP>' to avoid binding all interfaces. Keep PKI simple with easy-rsa for lab use." ;;
    2) echo "Host routes use /32 netmask. Verify loopback presence before pushing the route." ;;
    3) echo "Without 'server' directive, OpenVPN won’t allocate client addresses or routes." ;;
    4) echo "Confirm interface IP: ip -4 addr show ens4. Ensure systemd instance openvpn@server runs." ;;
    5) echo "Consistency matters: loopback IP and pushed route must match exactly (1.1.1.1/32)." ;;
    6) echo "Firewalls often block UDP/1194; open it and check with ss -lun plus ufw status." ;;
    *) echo -e "${FAIL} Unknown lab $lab" ;;
  esac
  echo "----------------------------------------"
}

# =========================
# INTERACTIVE MENU
# =========================
interactive_menu(){
  while true; do
    clear
    echo -e "${BOLD}Section 5 Labs Menu (OpenVPN)${NC}"
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
      1) read -rp "Lab (1-6): " lab; summary_for_lab "$lab"; apply_lab "$lab"; save_state lab "$lab"; read -rp "Press Enter..." ;;
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

# =========================
# MAIN
# =========================
main(){
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
  [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 <lab#> apply|check"; exit 2; }
  case "$2" in
    apply) apply_lab "$lab" ;;
    check) do_check "$lab" ;;
    *) echo -e "${FAIL} Use: apply | check"; exit 2 ;;
  esac
}
main "$@"
```
