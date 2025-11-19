#!/usr/bin/env bash
# Section 4 - DNS & Name Resolution Labs (modeled after Section 3)
# Labs:
# 1) Configure Creating Forward Zones
# 2) Configure Creating Reverse Zones
# 3) Configure DNS Caching with dnsmasq
# 4) Configure Split DNS Configuration (BIND views: internal/external)
# 5) Troubleshooting DNS
# 6) Setting Up a Local DNS Server (Bind9)

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
BASE_IF="ens4"

# Bind paths
BIND_CONF_LOCAL="/etc/bind/named.conf.local"
BIND_CONF_MAIN="/etc/bind/named.conf"
BIND_VIEWS_FILE="/etc/bind/named.conf.views"
BIND_ZONES_DIR="/etc/bind/zones"

# dnsmasq path
DNSMASQ_CONF="/etc/dnsmasq.d/lab.conf"

# Demo IPs for zone data
NS_IP="10.10.20.11"
WWW_IP="10.10.20.12"

# Colors/icons
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"; WARN="${YELLOW}[!]${NC}"

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

ensure_packages(){
  # Bind & utilities, dnsmasq, dig
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 bind9utils dnsutils dnsmasq
}

ensure_bind_dirs(){
  mkdir -p "$BIND_ZONES_DIR"
  touch "$BIND_CONF_LOCAL"
}

ensure_views_include(){
  # Ensure the main named.conf includes our views file once
  if ! grep -qF "$BIND_VIEWS_FILE" "$BIND_CONF_MAIN" 2>/dev/null; then
    echo "include \"$BIND_VIEWS_FILE\";" >> "$BIND_CONF_MAIN"
  fi
}

summary_for_lab(){
  local lab="$1"
  case "$lab" in
    1) cat <<EOF
${BOLD}Lab 1 — Forward Zone (lab.local)${NC}
- Create a master forward zone 'lab.local' with A records:
  - ns.lab.local -> ${NS_IP}
  - www.lab.local -> ${WWW_IP}
EOF
    ;;
    2) cat <<EOF
${BOLD}Lab 2 — Reverse Zone (20.10.10.in-addr.arpa)${NC}
- Create a master reverse zone for 10.10.20.0/24 with PTR records:
  - ${NS_IP} -> ns.lab.local
  - ${WWW_IP} -> www.lab.local
EOF
    ;;
    3) cat <<EOF
${BOLD}Lab 3 — DNS Cache with dnsmasq${NC}
- Configure dnsmasq to cache queries, listening on 127.0.0.1.
EOF
    ;;
    4) cat <<EOF
${BOLD}Lab 4 — Split DNS (BIND views)${NC}
- Configure internal/external views for 'lab.local':
  - INTERNAL (clients in 10.10.20.0/24): ns=${NS_IP}, www=${WWW_IP}, intranet=10.10.20.13
  - EXTERNAL (other clients): ns=${NS_IP}, www=8.8.8.8, intranet=NXDOMAIN
EOF
    ;;
    5) cat <<EOF
${BOLD}Lab 5 — Troubleshooting DNS${NC}
- Use dig/named-check* and logs to isolate and correct issues.
EOF
    ;;
    6) cat <<EOF
${BOLD}Lab 6 — Local DNS Server (BIND9)${NC}
- Install & enable Bind9, validate syntax, ensure port 53 is listening.
EOF
    ;;
    *) echo -e "${FAIL} Unknown lab $lab" ;;
  esac
}

# =========================
# APPLY FUNCTIONS
# =========================
lab1_apply(){
  ensure_packages; ensure_bind_dirs
  # Forward zone file
  write_file "${BIND_ZONES_DIR}/db.lab.local" 0644 <<'EOF'
$TTL 604800
@   IN  SOA ns.lab.local. admin.lab.local. (
        3        ; Serial
        604800   ; Refresh
        86400    ; Retry
        2419200  ; Expire
        604800 ) ; Negative Cache TTL
;
@       IN  NS  ns.lab.local.
ns      IN  A   10.10.20.11
www     IN  A   10.10.20.12
EOF
  # Zone declaration
  if ! grep -q 'zone "lab.local"' "$BIND_CONF_LOCAL"; then
    cat >> "$BIND_CONF_LOCAL" <<EOF
zone "lab.local" {
  type master;
  file "${BIND_ZONES_DIR}/db.lab.local";
};
EOF
  fi
  q systemctl restart bind9
}

lab2_apply(){
  ensure_packages; ensure_bind_dirs
  # Reverse zone file for 10.10.20.0/24 -> 20.10.10.in-addr.arpa
  write_file "${BIND_ZONES_DIR}/db.10.10.20" 0644 <<'EOF'
$TTL 604800
@   IN  SOA ns.lab.local. admin.lab.local. (
        3
        604800
        86400
        2419200
        604800 )
;
@       IN  NS  ns.lab.local.
11      IN  PTR ns.lab.local.
12      IN  PTR www.lab.local.
EOF
  if ! grep -q 'zone "20.10.10.in-addr.arpa"' "$BIND_CONF_LOCAL"; then
    cat >> "$BIND_CONF_LOCAL" <<EOF
zone "20.10.10.in-addr.arpa" {
  type master;
  file "${BIND_ZONES_DIR}/db.10.10.20";
};
EOF
  fi
  q systemctl restart bind9
}

lab3_apply(){
  ensure_packages
  write_file "${DNSMASQ_CONF}" 0644 <<'EOF'
# DNS caching lab config
cache-size=1000
listen-address=127.0.0.1
no-hosts
EOF
  q systemctl enable --now dnsmasq
  q systemctl restart dnsmasq
}

lab4_apply(){
  ensure_packages; ensure_bind_dirs; ensure_views_include
  # Internal/external zone files for split DNS
  write_file "${BIND_ZONES_DIR}/db.lab.local.internal" 0644 <<'EOF'
$TTL 604800
@   IN  SOA ns.lab.local. admin.lab.local. (
        5
        604800
        86400
        2419200
        604800 )
;
@         IN  NS  ns.lab.local.
ns        IN  A   10.10.20.11
www       IN  A   10.10.20.12
intranet  IN  A   10.10.20.13
EOF

  write_file "${BIND_ZONES_DIR}/db.lab.local.external" 0644 <<'EOF'
$TTL 604800
@   IN  SOA ns.lab.local. admin.lab.local. (
        5
        604800
        86400
        2419200
        604800 )
;
@         IN  NS  ns.lab.local.
ns        IN  A   10.10.20.11
www       IN  A   8.8.8.8
# intranet intentionally NOT defined externally
EOF

  # Views file (top-level, included by named.conf)
  write_file "${BIND_VIEWS_FILE}" 0644 <<'EOF'
acl internal_net { 10.10.20.0/24; };

view "internal" {
  match-clients { internal_net; };
  recursion yes;
  zone "lab.local" {
    type master;
    file "/etc/bind/zones/db.lab.local.internal";
  };
};

view "external" {
  match-clients { any; };
  recursion no;
  zone "lab.local" {
    type master;
    file "/etc/bind/zones/db.lab.local.external";
  };
};
EOF

  q systemctl restart bind9
}

lab5_apply(){
  # No-op: troubleshooting happens in checks/solutions
  :
}

lab6_apply(){
  ensure_packages; ensure_bind_dirs
  q systemctl enable --now bind9
}

# =========================
# CHECK FUNCTIONS
# =========================
lab1_check(){
  begin_check
  [[ -f "${BIND_ZONES_DIR}/db.lab.local" ]] && good "Forward zone file exists" || miss "Forward zone file missing"
  grep -q 'zone "lab.local"' "$BIND_CONF_LOCAL" && good "Forward zone declared in named.conf.local" || miss "Forward zone not declared"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkzone lab.local "${BIND_ZONES_DIR}/db.lab.local" >/dev/null 2>&1 && good "named-checkzone (lab.local) OK" || miss "named-checkzone failed for lab.local"
  dig @127.0.0.1 lab.local +short | grep -Eq '^10\.10\.20\.(11|12)$' && good "DNS resolves lab.local (A records present)" || miss "DNS does not resolve lab.local"
  end_check
}

lab2_check(){
  begin_check
  [[ -f "${BIND_ZONES_DIR}/db.10.10.20" ]] && good "Reverse zone file exists" || miss "Reverse zone file missing"
  grep -q 'zone "20.10.10.in-addr.arpa"' "$BIND_CONF_LOCAL" && good "Reverse zone declared" || miss "Reverse zone not declared"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkzone 20.10.10.in-addr.arpa "${BIND_ZONES_DIR}/db.10.10.20" >/dev/null 2>&1 && good "named-checkzone (reverse) OK" || miss "named-checkzone failed (reverse)"
  dig @127.0.0.1 -x "${NS_IP}" +short | grep -q '^ns\.lab\.local\.$' && good "PTR for ${NS_IP} -> ns.lab.local" || miss "Reverse DNS for ${NS_IP} failed"
  end_check
}

lab3_check(){
  begin_check
  systemctl is-active --quiet dnsmasq && good "dnsmasq is running" || miss "dnsmasq is not running"
  grep -q '^cache-size=1000' "${DNSMASQ_CONF}" && good "dnsmasq cache-size configured" || miss "dnsmasq cache-size not set"
  dig @127.0.0.1 www.lab.local +short | grep -q '^10\.10\.20\.12$' && good "dnsmasq resolves www.lab.local (cached/forwarded)" || miss "dnsmasq does not resolve www.lab.local"
  end_check
}

lab4_check(){
  begin_check
  grep -q 'view "internal"' "${BIND_VIEWS_FILE}" && good "Internal view present" || miss "Internal view not present"
  grep -q 'view "external"' "${BIND_VIEWS_FILE}" && good "External view present" || miss "External view not present"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkconf >/dev/null 2>&1 && good "named-checkconf OK" || miss "named-checkconf reports errors"

  # Validate internal answers via source IP simulation is tough without nsupdate/test clients.
  # We at least confirm both zone files exist and contain expected records.
  [[ -f "${BIND_ZONES_DIR}/db.lab.local.internal" ]] && grep -q '^intranet' "${BIND_ZONES_DIR}/db.lab.local.internal" && good "Internal zone defines intranet" || miss "Internal zone missing 'intranet'"
  [[ -f "${BIND_ZONES_DIR}/db.lab.local.external" ]] && ! grep -q '^intranet' "${BIND_ZONES_DIR}/db.lab.local.external" && good "External zone omits intranet" || miss "External zone unexpectedly defines 'intranet'"

  # Basic resolution check (using loopback)
  dig @127.0.0.1 lab.local +short | grep -Eq '^10\.10\.20\.(11|12)$' && good "Loopback resolves lab.local" || miss "Loopback failed to resolve lab.local"
  end_check
}

lab5_check(){
  begin_check
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkconf >/dev/null 2>&1 && good "named-checkconf OK" || miss "named-checkconf error"
  dig @127.0.0.1 lab.local +short | grep -Eq '^10\.10\.20\.(11|12)$' && good "Forward resolution OK" || miss "Forward resolution failed"
  dig @127.0.0.1 -x "${NS_IP}" +short | grep -q '^ns\.lab\.local\.$' && good "Reverse resolution OK" || miss "Reverse resolution failed"
  end_check
}

lab6_check(){
  begin_check
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkconf >/dev/null 2>&1 && good "named-checkconf OK" || miss "named-checkconf error"
  # Prefer ss over netstat (netstat may not exist)
  if command -v ss >/dev/null 2>&1; then
    ss -lntup | grep -E '(:53\s)|(:53$)' >/dev/null 2>&1 && good "Port 53 listening" || miss "Port 53 not listening"
  else
    netstat -ln | grep -q ":53" && good "Port 53 listening" || miss "Port 53 not listening"
  fi
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
  # Remove dnsmasq conf & restart
  rm -f "${DNSMASQ_CONF}"
  q systemctl restart dnsmasq

  # Remove views file and comment include
  rm -f "${BIND_VIEWS_FILE}"
  # (leave include line; named-checkconf will still pass without file)

  # Remove zone stubs
  rm -f "${BIND_ZONES_DIR}/db.lab.local" \
        "${BIND_ZONES_DIR}/db.10.10.20" \
        "${BIND_ZONES_DIR}/db.lab.local.internal" \
        "${BIND_ZONES_DIR}/db.lab.local.external"

  # Remove zone declarations
  sed -i '/zone "lab.local"/,/};/d' "${BIND_CONF_LOCAL}" || true
  sed -i '/zone "20\.10\.10\.in-addr\.arpa"/,/};/d' "${BIND_CONF_LOCAL}" || true

  q systemctl restart bind9
  : > "${STATE_FILE}" 2>/dev/null || true
  echo -e "${OK} Reset complete"
}

status(){
  local lab
  lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: ${lab}"
  echo -e "${INFO} Bind9 status:"; systemctl status bind9 --no-pager || true
  echo -e "${INFO} dnsmasq status:"; systemctl status dnsmasq --no-pager || true
}

print_list(){
  cat <<EOF
${BOLD}Section 4 Labs${NC}
1. Configure Creating Forward Zones
2. Configure Creating Reverse Zones
3. Configure DNS Caching with dnsmasq
4. Configure Split DNS Configuration (BIND views)
5. Troubleshooting DNS
6. Setting Up a Local DNS Server (Bind9)

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
# SOLUTIONS (step-by-step)
# =========================
print_solution(){
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1) cat <<'EOS'
Step-by-step (Forward Zone):
1) Create forward zone file:
/etc/bind/zones/db.lab.local
2) Declare zone in /etc/bind/named.conf.local:
zone "lab.local" { type master; file "/etc/bind/zones/db.lab.local"; };
3) Restart Bind9:
systemctl restart bind9
4) Verify:
nmcli dev status
nmcli general status
named-checkzone lab.local /etc/bind/zones/db.lab.local
dig @127.0.0.1 lab.local +short
EOS
    ;;
    2) cat <<'EOS'
Step-by-step (Reverse Zone):
1) Create reverse zone file:
/etc/bind/zones/db.10.10.20
2) Declare zone in /etc/bind/named.conf.local:
zone "20.10.10.in-addr.arpa" { type master; file "/etc/bind/zones/db.10.10.20"; };
3) Restart Bind9:
systemctl restart bind9
4) Verify:
nmcli dev status
nmcli general status
named-checkzone 20.10.10.in-addr.arpa /etc/bind/zones/db.10.10.20
dig @127.0.0.1 -x 10.10.20.11 +short
EOS
    ;;
    3) cat <<'EOS'
Step-by-step (dnsmasq caching):
1) Install & configure:
apt-get install -y dnsmasq
echo -e "cache-size=1000\nlisten-address=127.0.0.1" > /etc/dnsmasq.d/lab.conf
2) Restart:
systemctl restart dnsmasq
3) Verify:
nmcli dev status
nmcli general status
systemctl status dnsmasq --no-pager
dig @127.0.0.1 www.lab.local +short
EOS
    ;;
    4) cat <<'EOS'
Step-by-step (Split DNS with views):
1) Prepare zone files:
/etc/bind/zones/db.lab.local.internal
/etc/bind/zones/db.lab.local.external
2) Create views file:
/etc/bind/named.conf.views
3) Include views in /etc/bind/named.conf (add once):
include "/etc/bind/named.conf.views";
4) Restart Bind9:
systemctl restart bind9
5) Verify:
nmcli dev status
nmcli general status
named-checkconf
# Optional deep checks:
named-checkzone lab.local /etc/bind/zones/db.lab.local.internal
named-checkzone lab.local /etc/bind/zones/db.lab.local.external
# Note: client-based testing of views requires queries from internal_net (10.10.20.0/24)
EOS
    ;;
    5) cat <<'EOS'
Step-by-step (Troubleshooting DNS):
1) Service health:
systemctl status bind9 --no-pager
journalctl -u bind9 -b -n 100
2) Syntax:
named-checkconf
named-checkzone lab.local /etc/bind/zones/db.lab.local
named-checkzone 20.10.10.in-addr.arpa /etc/bind/zones/db.10.10.20
3) Resolution:
dig @127.0.0.1 lab.local +short
dig @127.0.0.1 -x 10.10.20.11 +short
4) Fix:
- Correct zone records/syntax, increment Serial, restart bind9.
- If “connection refused”, ensure port 53 is listening (ss -lntup | grep ':53').
EOS
    ;;
    6) cat <<'EOS'
Step-by-step (Local DNS server):
1) Install and enable:
apt-get install -y bind9 bind9utils dnsutils
systemctl enable --now bind9
2) Validate:
nmcli dev status
nmcli general status
named-checkconf
ss -lntup | grep ':53'
3) (Optional) Create zones (see Labs 1 & 2), then verify with named-checkzone & dig.
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
    1) echo "Use named-checkzone before restarting Bind9; always bump the Serial when editing zone files." ;;
    2) echo "PTR names must end with a dot (FQDN) in zone files; dig -x helps confirm reverse mapping." ;;
    3) echo "dnsmasq is great for caching; keep cache-size modest in small labs and verify with dig @127.0.0.1." ;;
    4) echo "Views match by client IP; to truly test, query from an address in 10.10.20.0/24 vs outside." ;;
    5) echo "Check /var/log/syslog for BIND messages; syntax errors show line numbers for quick fixes." ;;
    6) echo "If port 53 isn’t listening, check named.conf includes and apparmor/SELinux in hardened images." ;;
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
    echo -e "${BOLD}Section 4 Labs Menu${NC}"
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
