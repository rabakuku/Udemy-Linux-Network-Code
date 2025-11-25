
#!/usr/bin/env bash
# ============================================================
# Section 5 — SSL VPN (OpenVPN) Labs (PAM user auth only)
# - Idempotent Easy-RSA for server TLS (no client certs required)
# - Conditional 'local' directive
# - Modern ta.key generation (OpenVPN 2.6+)
# - Smart unit/config-path detection (prefers /etc/openvpn/server.conf)
# - NO subtitles printed on apply
# - Client issuer outputs username/password .ovpn (no <cert>/<key>)
# - Interactive menu + Solutions
# ============================================================

# ---- Root check ----
if (( EUID != 0 )); then
  echo -e "\e[33m[!] Please run as root: sudo $0 $*\e[0m"
  exit 1
fi

# ---- Strict mode + helpful trap ----
if [[ -n "${LABS_DEBUG:-}" ]]; then set -x; fi
set -Eeuo pipefail
trap 'rc=$?; if [[ $rc -ne 0 ]]; then
  echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2
fi' ERR

# ===== Paths / constants =====
LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"
OPENVPN_DIR="/etc/openvpn"
SERVICE_UNIT=""
CONF_PATH=""
OPENVPN_STATUS="/var/log/openvpn-status.log"

# Easy-RSA (packaged) and managed PKI dir
EASYRSA_SRC="/usr/share/easy-rsa"
PKI_DIR="${OPENVPN_DIR}/pki"
EASYRSA_DIR="${PKI_DIR}/easyrsa"

# Network constants
IFACE="ens4"
ALT_IFACE="ens3"
LO_GOOD_IP="1.1.1.1"
LO_BAD_IP="2.2.2.2"
VPN_NET="10.8.0.0"
VPN_MASK="255.255.255.0"

# Colors/icons
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"

# ===== Helpers =====
q() { "$@" >/dev/null 2>&1 || true; }
mkdirs() { mkdir -p "$LAB_ROOT"; }
save_state() { local k="$1" v="$2"; mkdirs; touch "$STATE_FILE"
  if grep -q "^${k}=" "$STATE_FILE"; then
    sed -i "s/^${k}=.*/${k}=${v}/" "$STATE_FILE"
  else
    echo "${k}=${v}" >> "$STATE_FILE"
  fi
}
get_state() { local k="$1"; [[ -f "$STATE_FILE" ]] || { echo ""; return 0; }
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
write_file() { # write_file <path> <mode>, content from stdin
  local path="$1" mode="$2"
  umask 022
  cat >"$path"
  chmod "$mode" "$path" || true
  chown root:root "$path" || true
}
iface_ip() {
  ip -4 addr show "$1" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}
ensure_packages() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openvpn easy-rsa iproute2 ufw
}
ensure_loopback_good() { ip addr add "${LO_GOOD_IP}/32" dev lo 2>/dev/null || true; }
ensure_loopback_bad() { ip addr add "${LO_BAD_IP}/32" dev lo 2>/dev/null || true; }
remove_loopbacks() {
  ip addr del "${LO_GOOD_IP}/32" dev lo 2>/dev/null || true
  ip addr del "${LO_BAD_IP}/32" dev lo 2>/dev/null || true
}
local_line() { local ip="$1"; if [[ -n "$ip" ]]; then echo "local ${ip}"; fi; }

# ===== Smart detection: prefer /etc/openvpn/server.conf and pick best unit =====
detect_unit_and_paths() {
  local has_umbrella=0 has_at=0 has_server_at=0
  systemctl list-unit-files | grep -q '^openvpn\.service' && has_umbrella=1
  systemctl list-unit-files | grep -q '^openvpn@\.service' && has_at=1
  systemctl list-unit-files | grep -q '^openvpn-server@\.service' && has_server_at=1

  # Prefer /etc/openvpn/server.conf if present
  if [[ -f /etc/openvpn/server.conf ]]; then
    CONF_PATH="/etc/openvpn/server.conf"
    if (( has_umbrella )); then
      SERVICE_UNIT="openvpn.service"
      if [[ -f /etc/default/openvpn ]]; then
        sed -i 's/^AUTOSTART=.*/AUTOSTART="server"/' /etc/default/openvpn || true
      else
        echo 'AUTOSTART="server"' > /etc/default/openvpn
      fi
    elif (( has_at )); then
      SERVICE_UNIT="openvpn@server.service"
    elif (( has_server_at )); then
      SERVICE_UNIT="openvpn-server@server.service"
      mkdir -p /etc/openvpn/server
      ln -sf /etc/openvpn/server.conf /etc/openvpn/server/server.conf
    else
      SERVICE_UNIT="openvpn.service"
    fi

  # If only template path exists, align unit and (optionally) link server.conf
  elif [[ -f /etc/openvpn/server/server.conf ]]; then
    if (( has_server_at )); then
      SERVICE_UNIT="openvpn-server@server.service"
      CONF_PATH="/etc/openvpn/server/server.conf"
    elif (( has_at )); then
      SERVICE_UNIT="openvpn@server.service"
      ln -sf /etc/openvpn/server/server.conf /etc/openvpn/server.conf
      CONF_PATH="/etc/openvpn/server.conf"
    else
      SERVICE_UNIT="openvpn.service"
      ln -sf /etc/openvpn/server/server.conf /etc/openvpn/server.conf
      CONF_PATH="/etc/openvpn/server.conf"
      if [[ -f /etc/default/openvpn ]]; then
        sed -i 's/^AUTOSTART=.*/AUTOSTART="server"/' /etc/default/openvpn || true
      else
        echo 'AUTOSTART="server"' > /etc/default/openvpn
      fi
    fi

  # Default: create /etc/openvpn/server.conf and pick the best unit
  else
    if (( has_umbrella )); then
      SERVICE_UNIT="openvpn.service"
      CONF_PATH="/etc/openvpn/server.conf"
      if [[ -f /etc/default/openvpn ]]; then
        sed -i 's/^AUTOSTART=.*/AUTOSTART="server"/' /etc/default/openvpn || true
      else
        echo 'AUTOSTART="server"' > /etc/default/openvpn
      fi
    elif (( has_at )); then
      SERVICE_UNIT="openvpn@server.service"
      CONF_PATH="/etc/openvpn/server.conf"
    elif (( has_server_at )); then
      SERVICE_UNIT="openvpn-server@server.service"
      mkdir -p /etc/openvpn/server
      CONF_PATH="/etc/openvpn/server/server.conf"
    else
      SERVICE_UNIT="openvpn.service"
      CONF_PATH="/etc/openvpn/server.conf"
      echo 'AUTOSTART="server"' > /etc/default/openvpn
    fi
  fi

  export SERVICE_UNIT CONF_PATH OPENVPN_STATUS
}

# ===== Idempotent Easy-RSA PKI (server TLS only) =====
ensure_pki() {
  mkdir -p "$PKI_DIR"
  if [[ ! -d "$EASYRSA_DIR" ]]; then cp -r "$EASYRSA_SRC" "$EASYRSA_DIR"; fi
  pushd "$EASYRSA_DIR" >/dev/null
  export EASYRSA_BATCH=1
  if [[ ! -d "$EASYRSA_DIR/pki" ]]; then ./easyrsa init-pki; fi
  if [[ ! -f "$EASYRSA_DIR/pki/ca.crt" || ! -f "$EASYRSA_DIR/pki/private/ca.key" ]]; then
    export EASYRSA_REQ_CN="Easy-RSA CA"
    ./easyrsa build-ca nopass
  fi
  if [[ ! -f "$EASYRSA_DIR/pki/dh.pem" ]]; then ./easyrsa gen-dh; fi
  if [[ ! -f "$EASYRSA_DIR/pki/issued/server.crt" || ! -f "$EASYRSA_DIR/pki/private/server.key" ]]; then
    export EASYRSA_REQ_CN="server"
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
  fi
  if [[ ! -f "${PKI_DIR}/ta.key" ]]; then
    # OpenVPN 2.6+ preferred syntax (no deprecation warning)
    openvpn --genkey secret "${PKI_DIR}/ta.key"
  fi
  popd >/dev/null
  ln -sf "${EASYRSA_DIR}/pki/ca.crt" "${OPENVPN_DIR}/ca.crt"
  ln -sf "${EASYRSA_DIR}/pki/issued/server.crt" "${OPENVPN_DIR}/server.crt"
  ln -sf "${EASYRSA_DIR}/pki/private/server.key" "${OPENVPN_DIR}/server.key"
  ln -sf "${EASYRSA_DIR}/pki/dh.pem" "${OPENVPN_DIR}/dh.pem"
  ln -sf "${PKI_DIR}/ta.key" "${OPENVPN_DIR}/ta.key"
  chmod 644 "${OPENVPN_DIR}/ca.crt" "${OPENVPN_DIR}/server.crt" "${OPENVPN_DIR}/dh.pem" || true
  chmod 600 "${OPENVPN_DIR}/server.key" "${OPENVPN_DIR}/ta.key" || true
}

# ---- Config validation ----
validate_config() {
  local missing=0
  for f in "${CONF_PATH}" \
    "${OPENVPN_DIR}/ca.crt" "${OPENVPN_DIR}/server.crt" \
    "${OPENVPN_DIR}/server.key" "${OPENVPN_DIR}/dh.pem" "${OPENVPN_DIR}/ta.key"
  do
    if [[ ! -f "$f" ]]; then echo -e "\e[31m✗ Missing: $f\e[0m" >&2; missing=1; fi
  done
  if [[ $missing -ne 0 ]]; then
    echo -e "\e[31m✗ Config validation failed—see missing files above.\e[0m" >&2
    exit 3
  fi
}

enable_openvpn() {
  validate_config
  q systemctl enable "${SERVICE_UNIT}"
  if ! systemctl restart "${SERVICE_UNIT}"; then
    echo -e "\e[33m[!] ${SERVICE_UNIT} restart failed. Journal (last 50 lines):\e[0m"
    journalctl -u "${SERVICE_UNIT}" -n 50 --no-pager || true
    # Some labs may intentionally create run-time faults
  fi
}

disable_openvpn() {
  q systemctl stop "${SERVICE_UNIT}"
  q systemctl disable "${SERVICE_UNIT}"
}

ufw_block_1194() { q ufw --force enable; ufw deny 1194/udp || true; }
ufw_allow_1194() { q ufw --force enable; ufw delete deny 1194/udp 2>/dev/null || true; ufw allow 1194/udp || true; }

# =========================
# APPLY FUNCTIONS
# =========================
pam_block() {
cat <<'PAM'
client-cert-not-required
verify-client-cert none
username-as-common-name
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so login
PAM
}

lab1_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${local_ip}")
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
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  enable_openvpn
}

lab2_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${local_ip}")
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
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  enable_openvpn
}

lab3_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${local_ip}")
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
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  enable_openvpn
}

lab4_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; ensure_loopback_good
  alt_ip="$(iface_ip "${ALT_IFACE}")"; [[ -z "$alt_ip" ]] && alt_ip="0.0.0.0"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${alt_ip}")
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
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  enable_openvpn
}

lab5_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; remove_loopbacks; ensure_loopback_bad
  local_ip="$(iface_ip "$IFACE")"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${local_ip}")
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
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  enable_openvpn
}

lab6_apply() {
  ensure_packages; detect_unit_and_paths; ensure_pki; ensure_loopback_good
  local_ip="$(iface_ip "$IFACE")"
  write_file "${CONF_PATH}" 0644 <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
$(local_line "${local_ip}")
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
key ${OPENVPN_DIR}/server.key}
dh ${OPENVPN_DIR}/dh.pem
tls-auth ${OPENVPN_DIR}/ta.key 0
auth SHA256
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
$(pam_block)
EOF
  ufw_block_1194
  enable_openvpn
}

# =========================
# CHECK FUNCTIONS
# =========================
lab1_check() {
  begin_check; detect_unit_and_paths
  systemctl is-active --quiet "${SERVICE_UNIT}" && good "OpenVPN server is running" || miss "OpenVPN server not running"
  grep -q "^server ${VPN_NET} ${VPN_MASK}" "${CONF_PATH}" && good "VPN subnet configured" || miss "VPN subnet missing"
  grep -q "push \"route ${LO_GOOD_IP} 255.255.255.255\"" "${CONF_PATH}" && good "Route push present" || miss "Route push missing"
  ip addr show lo | grep -q "${LO_GOOD_IP}" && good "Loopback present" || miss "Loopback missing"
  ss -lun | grep -q ":1194" && good "UDP/1194 listening" || miss "UDP/1194 not listening"
  end_check
}

lab2_check() {
  begin_check; detect_unit_and_paths
  if grep -q "push \"route ${LO_BAD_IP} 255.255.255.255\"" "${CONF_PATH}"; then
    miss "Detected wrong route ${LO_BAD_IP}"
  else
    if grep -q "push \"route ${LO_GOOD_IP} 255.255.255.255\"" "${CONF_PATH}"; then
      good "Route fixed to ${LO_GOOD_IP}"
    else
      miss "Route push missing"
    fi
  fi
  end_check
}

lab3_check() {
  begin_check; detect_unit_and_paths
  if grep -q "^server " "${CONF_PATH}"; then
    good "Server directive present"
  else
    miss "Server directive missing"
  fi
  end_check
}

lab4_check() {
  begin_check; detect_unit_and_paths
  bound_ip="$(awk '/^local /{print $2}' "${CONF_PATH}" | head -n1 || true)"
  if [[ -z "$bound_ip" ]]; then
    miss "No local bind configured"
  else
    good "Local bind: ${bound_ip}"
  fi
  correct_ip="$(iface_ip "${IFACE}")"
  if [[ "$bound_ip" == "$correct_ip" ]]; then
    good "Bound to ens4"
  else
    miss "Not bound to ens4"
  fi
  end_check
}

lab5_check() {
  begin_check
  ip addr show lo | grep -q "${LO_BAD_IP}" && miss "Wrong loopback present" || good "Wrong loopback not present"
  ip addr show lo | grep -q "${LO_GOOD_IP}" && good "Correct loopback present" || miss "Correct loopback not present"
  end_check
}

lab6_check() {
  begin_check
  ufw status | grep -q "1194/udp.*DENY" && miss "The Wall" || good "UFW not denying UDP/1194"
  end_check
}

# =========================
# SOLUTIONS (step-by-step fixes)
# =========================
print_solution() {
  detect_unit_and_paths
  local lab="$1"
  echo "------ Solutions for Lab ${lab} ------"
  # Step 1: assign ens4 interface an IP
  cat <<'EOS'
# assign ens4 interface an IP:
nano /etc/netplan/section5-labs.yaml
network:
  version: 2
  ethernets:
    ens4:
      addresses:
        - 10.10.10.1/24
netplan apply
EOS
  case "$lab" in
    1)
      cat <<'EOS'
sudo ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true
grep '^server 10.8.0.0 255.255.255.0' /etc/openvpn/server.conf
grep 'push "route 1.1.1.1 255.255.255.255"' /etc/openvpn/server.conf
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
sudo systemctl status openvpn@server --no-pager || true
sudo systemctl status openvpn --no-pager || true
sudo systemctl status openvpn-server@server --no-pager || true
EOS
      ;;
    2)
      cat <<'EOS'
sudo sed -i 's/push "route .*/push "route 1.1.1.1 255.255.255.255"/' /etc/openvpn/server.conf
sudo ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true
sudo ip addr del 2.2.2.2/32 dev lo 2>/dev/null || true
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
grep 'push "route 1.1.1.1 255.255.255.255"' /etc/openvpn/server.conf
ip addr show lo | grep '1.1.1.1'
EOS
      ;;
    3)
      cat <<'EOS'
echo 'server 10.8.0.0 255.255.255.0' | sudo tee -a /etc/openvpn/server.conf >/dev/null
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
grep '^server 10.8.0.0 255.255.255.0' /etc/openvpn/server.conf
EOS
      ;;
    4)
      cat <<'EOS'
ENS4_IP=$(ip -4 addr show ens4 | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
sudo sed -i "s/^local .*/local ${ENS4_IP}/" /etc/openvpn/server.conf
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
grep '^local ' /etc/openvpn/server.conf
ss -lun | grep ':1194' || echo "UDP/1194 not listening"
EOS
      ;;
    5)
      cat <<'EOS'
sudo ip addr del 2.2.2.2/32 dev lo 2>/dev/null || true
sudo ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true
sudo sed -i 's/push "route .*/push "route 1.1.1.1 255.255.255.255"/' /etc/openvpn/server.conf
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
ip addr show lo | grep '1.1.1.1'
grep 'push "route 1.1.1.1 255.255.255.255"' /etc/openvpn/server.conf
EOS
      ;;
    6)
      cat <<'EOS'
sudo ufw --force enable
sudo ufw allow 1194/udp
sudo systemctl restart openvpn@server || true
sudo systemctl restart openvpn || true
sudo systemctl restart openvpn-server@server || true
sudo ufw status | grep '1194/udp'
ss -lun | grep ':1194' || echo "UDP/1194 not listening"
EOS
      ;;
    *)
      echo -e "${FAIL} Unknown lab $lab"
      ;;
  esac
  echo "----------------------------------------"
}

# =========================
# APPLY (no subtitles printed)
# =========================
apply_lab() {
  local lab="$1"
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

do_check() {
  local lab="$1"; detect_unit_and_paths
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
reset_all() {
  detect_unit_and_paths
  disable_openvpn || true
  ufw delete allow 1194/udp 2>/dev/null || true
  ufw delete deny 1194/udp 2>/dev/null || true
  rm -f "${CONF_PATH}" "${OPENVPN_STATUS}"
  rm -rf "${PKI_DIR}"
  remove_loopbacks
  : > "${STATE_FILE}" 2>/dev/null || true
  rm -f /etc/netplan/section5-labs.yaml
  echo -e "${OK} Reset complete"
}

status() {
  detect_unit_and_paths
  local lab; lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Using unit: ${SERVICE_UNIT}"
  echo -e "${INFO} Config path: ${CONF_PATH}"
  echo -e "${INFO} OpenVPN status:"; systemctl status "${SERVICE_UNIT}" --no-pager || true
  echo -e "${INFO} UFW status:"; ufw status || true
  echo -e "${INFO} Loopback IPs:"; ip addr show lo | sed -n 's/^\s*inet\s*\([0-9./]*\).*/\1/p'
  echo -e "${INFO} Interface ${IFACE} IP:"; iface_ip "${IFACE}" || true
}

print_list() {
  cat <<EOF
Section 5 Labs — OpenVPN SSL VPN (PAM user auth)
1. Troubleshooting 1
2. Troubleshooting 2
3. Troubleshooting 3
4. Troubleshooting 4
5. Troubleshooting 5
6. Troubleshooting 6
Usage:
  sudo $0 <lab#> apply
  sudo $0 <lab#> check
  sudo $0 reset
  sudo $0 status
  sudo $0 list
  sudo $0 solutions <lab#>
  sudo $0 client-issue <name> <server_ip_or_dns> <port> > client.ovpn
  sudo $0 menu   # interactive menu
EOF
}

# =========================
# OPTIONAL: Issue client cert and emit username/password .ovpn
# Usage: client-issue <name> <server_host_or_ip> <port> > client.ovpn
# =========================
client_issue() {
  local NAME="${1:-client1}" SERVER_HOST="${2:-10.10.10.1}" PORT="${3:-1194}"
  detect_unit_and_paths; ensure_pki
  pushd "${EASYRSA_DIR}" >/dev/null
  export EASYRSA_BATCH=1 EASYRSA_REQ_CN="${NAME}"
  if [[ ! -f "pki/issued/${NAME}.crt" || ! -f "pki/private/${NAME}.key" ]]; then
    ./easyrsa gen-req "${NAME}" nopass
    ./easyrsa sign-req client "${NAME}"
  fi
  popd >/dev/null
  local CA="${OPENVPN_DIR}/ca.crt"
  local TA="${OPENVPN_DIR}/ta.key"
  cat <<EOF
client
dev tun
proto udp
remote ${SERVER_HOST} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
verb 3
auth-user-pass
tls-auth ta.key 1
<ca>
$(cat "${CA}")
</ca>
<tls-auth>
$(cat "${TA}")
</tls-auth>
EOF
}

# =========================
# INTERACTIVE MENU (with Solutions)
# =========================
interactive_menu() {
  detect_unit_and_paths
  while true; do
    clear
    echo "=== Section 5 Labs Menu (OpenVPN, PAM user auth) ==="
    echo "1) Apply Lab"
    echo "2) Check Lab"
    echo "3) Reset"
    echo "4) Status"
    echo "5) List Labs"
    echo "6) Solutions"
    echo "7) Client Issue (.ovpn)"
    echo "q) Quit"
    read -rp "Select option: " opt
    case "$opt" in
      1)
        read -rp "Lab (1-6): " lab
        apply_lab "$lab"
        read -rp "Press Enter..." ;;
      2)
        read -rp "Lab (1-6): " lab
        do_check "$lab"
        read -rp "Press Enter..." ;;
      3)
        reset_all
        read -rp "Press Enter..." ;;
      4)
        status
        read -rp "Press Enter..." ;;
      5)
        print_list
        read -rp "Press Enter..." ;;
      6)
        read -rp "Lab (1-6): " lab
        print_solution "$lab"
        read -rp "Press Enter..." ;;
      7)
        read -rp "Client name (e.g., client1): " name
        read -rp "Server host/IP (default 10.10.10.1): " host
        host="${host:-10.10.10.1}"
        read -rp "Port (default 1194): " port
        port="${port:-1194}"
        read -rp "Output file path (leave blank to print to screen): " out
        if [[ -n "$out" ]]; then
          client_issue "$name" "$host" "$port" > "$out"
          echo -e "${OK} Wrote ${out}"
        else
          client_issue "$name" "$host" "$port"
        fi
        read -rp "Press Enter..." ;;
      q|Q)
        exit 0 ;;
      *)
        echo "Invalid selection"; sleep 1 ;;
    esac
  done
}

# =========================
# MAIN
# =========================
main() {
  mkdirs
  if [[ $# -lt 1 ]]; then
    interactive_menu
    exit 0
  fi
  case "$1" in
    menu)      interactive_menu; exit 0 ;;
    list)      detect_unit_and_paths; print_list; exit 0 ;;
    status)    status; exit 0 ;;
    reset)     reset_all; exit 0 ;;
    solutions) [[ $# -ne 2 ]] && { echo -e "${FAIL} Usage: $0 solutions <lab#>"; exit 2; }
               print_solution "$2"; exit 0 ;;
    client-issue)
               [[ $# -lt 2 ]] && { echo -e "${FAIL} Usage: $0 client-issue <name> [server_host] [port]"; exit 2; }
               client_issue "${2}" "${3:-10.10.10.1}" "${4:-1194}"; exit 0 ;;
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
