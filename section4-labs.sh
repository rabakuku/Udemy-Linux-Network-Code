#!/usr/bin/env bash
# Section 4 - DNS & Name Resolution Labs (modeled after Section 3)
# Labs:
# 1) Configure Creating Forward Zones
# 2) Configure Creating Reverse Zones
# 3) Configure DNS Caching with dnsmasq
# 4) Configure Split DNS Configuration
# 5) Troubleshooting DNS
# 6) Setting Up a Local DNS Server (Bind9)

if (( EUID != 0 )); then
  echo -e "\e[33m[!] Please run as root: sudo $0 $*\e[0m"
  exit 1
fi

set -Eeuo pipefail
trap 'rc=$?; if [[ $rc -ne 0 ]]; then
  echo -e "\e[31m✗ Error on line $LINENO while running: ${BASH_COMMAND}\e[0m" >&2
fi' ERR

LAB_ROOT="/etc/labs-menu"
STATE_FILE="${LAB_ROOT}/state"
BASE_IF="ens4"
DNS_ZONE_DIR="/etc/bind/zones"
DNSMASQ_CONF="/etc/dnsmasq.d/lab.conf"
BIND_CONF="/etc/bind/named.conf.local"
SPLIT_CONF="/etc/bind/named.conf.options"

GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; BOLD="\e[1m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"; WARN="${YELLOW}[!]${NC}"

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

summary_for_lab(){
  local lab="$1"
  case "$lab" in
    1) echo -e "${BOLD}Lab 1: Configure Creating Forward Zones${NC}\n- Create a forward DNS zone for lab.local." ;;
    2) echo -e "${BOLD}Lab 2: Configure Creating Reverse Zones${NC}\n- Create a reverse DNS zone for 10.10.20.0/24." ;;
    3) echo -e "${BOLD}Lab 3: Configure DNS Caching with dnsmasq${NC}\n- Set up dnsmasq to cache DNS queries." ;;
    4) echo -e "${BOLD}Lab 4: Configure Split DNS Configuration${NC}\n- Configure Bind9 for split DNS (internal/external views)." ;;
    5) echo -e "${BOLD}Lab 5: Troubleshooting DNS${NC}\n- Diagnose and fix DNS resolution issues." ;;
    6) echo -e "${BOLD}Lab 6: Setting Up a Local DNS Server (Bind9)${NC}\n- Install and configure Bind9 as a local DNS server." ;;
    *) ;;
  esac
}

# =========================
# APPLY FUNCTIONS
# =========================
lab1_apply(){
  mkdir -p "$DNS_ZONE_DIR"
  cat > "$DNS_ZONE_DIR/db.lab.local" <<EOF
\$TTL    604800
@       IN      SOA     ns.lab.local. admin.lab.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.lab.local.
ns      IN      A       10.10.20.11
www     IN      A       10.10.20.12
EOF
  grep -q "zone \"lab.local\"" "$BIND_CONF" || echo 'zone "lab.local" { type master; file "/etc/bind/zones/db.lab.local"; };' >> "$BIND_CONF"
  q systemctl restart bind9
}
lab2_apply(){
  mkdir -p "$DNS_ZONE_DIR"
  cat > "$DNS_ZONE_DIR/db.10.10.20" <<EOF
\$TTL    604800
@       IN      SOA     ns.lab.local. admin.lab.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.lab.local.
11      IN      PTR     ns.lab.local.
12      IN      PTR     www.lab.local.
EOF
  grep -q "zone \"20.10.10.in-addr.arpa\"" "$BIND_CONF" || echo 'zone "20.10.10.in-addr.arpa" { type master; file "/etc/bind/zones/db.10.10.20"; };' >> "$BIND_CONF"
  q systemctl restart bind9
}
lab3_apply(){
  apt-get install -y dnsmasq
  cat > "$DNSMASQ_CONF" <<EOF
cache-size=1000
listen-address=127.0.0.1
EOF
  q systemctl restart dnsmasq
}
lab4_apply(){
  mkdir -p "$DNS_ZONE_DIR"
  cat > "$SPLIT_CONF" <<EOF
options {
    directory "/var/cache/bind";
    allow-query { any; };
    recursion yes;
    forwarders { 8.8.8.8; };
    listen-on { any; };
    view "internal" {
        match-clients { 10.10.20.0/24; };
        recursion yes;
        zone "lab.local" { type master; file "/etc/bind/zones/db.lab.local"; };
    };
    view "external" {
        match-clients { any; };
        recursion no;
        zone "lab.local" { type master; file "/etc/bind/zones/db.lab.local"; };
    };
};
EOF
  q systemctl restart bind9
}
lab5_apply(){
  # No-op: troubleshooting is check-only
  :
}
lab6_apply(){
  apt-get install -y bind9
  mkdir -p "$DNS_ZONE_DIR"
  q systemctl enable --now bind9
}

# =========================
# CHECK FUNCTIONS
# =========================
lab1_check(){
  begin_check
  [[ -f "$DNS_ZONE_DIR/db.lab.local" ]] && good "Forward zone file exists" || miss "Forward zone file missing"
  grep -q "zone \"lab.local\"" "$BIND_CONF" && good "Bind9 forward zone configured" || miss "Bind9 forward zone not configured"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  dig @127.0.0.1 lab.local +short | grep -qE "10.10.20.11|10.10.20.12" && good "DNS resolves lab.local" || miss "DNS does not resolve lab.local"
  end_check
}
lab2_check(){
  begin_check
  [[ -f "$DNS_ZONE_DIR/db.10.10.20" ]] && good "Reverse zone file exists" || miss "Reverse zone file missing"
  grep -q "zone \"20.10.10.in-addr.arpa\"" "$BIND_CONF" && good "Bind9 reverse zone configured" || miss "Bind9 reverse zone not configured"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  dig @127.0.0.1 -x 10.10.20.11 +short | grep -q "ns.lab.local." && good "Reverse DNS resolves 10.10.20.11" || miss "Reverse DNS does not resolve 10.10.20.11"
  end_check
}
lab3_check(){
  begin_check
  systemctl is-active --quiet dnsmasq && good "dnsmasq is running" || miss "dnsmasq is not running"
  grep -q "cache-size=1000" "$DNSMASQ_CONF" && good "dnsmasq cache-size set" || miss "dnsmasq cache-size not set"
  dig @127.0.0.1 www.lab.local +short | grep -q "10.10.20.12" && good "dnsmasq resolves www.lab.local" || miss "dnsmasq does not resolve www.lab.local"
  end_check
}
lab4_check(){
  begin_check
  grep -q "view \"internal\"" "$SPLIT_CONF" && good "Split DNS internal view configured" || miss "Split DNS internal view not configured"
  grep -q "view \"external\"" "$SPLIT_CONF" && good "Split DNS external view configured" || miss "Split DNS external view not configured"
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  dig @127.0.0.1 lab.local +short | grep -qE "10.10.20.11|10.10.20.12" && good "Internal DNS resolves lab.local" || miss "Internal DNS does not resolve lab.local"
  end_check
}
lab5_check(){
  begin_check
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  dig @127.0.0.1 lab.local +short | grep -qE "10.10.20.11|10.10.20.12" && good "DNS resolves lab.local" || miss "DNS does not resolve lab.local"
  dig @127.0.0.1 -x 10.10.20.11 +short | grep -q "ns.lab.local." && good "Reverse DNS resolves 10.10.20.11" || miss "Reverse DNS does not resolve 10.10.20.11"
  end_check
}
lab6_check(){
  begin_check
  systemctl is-active --quiet bind9 && good "Bind9 is running" || miss "Bind9 is not running"
  named-checkconf && good "Bind9 config syntax OK" || miss "Bind9 config syntax error"
  netstat -ln | grep -q ":53" && good "Bind9 listening on port 53" || miss "Bind9 not listening on port 53"
  end_check
}

# =========================
# SOLUTIONS
# =========================
print_solution(){
  local lab="$1"
  echo -e "${BOLD}Solution for Lab ${lab}${NC}"
  echo "----------------------------------------"
  case "$lab" in
    1)
      cat <<'EOS'
Step-by-step:
1. Create forward zone file: /etc/bind/zones/db.lab.local
2. Add zone to /etc/bind/named.conf.local:
   zone "lab.local" { type master; file "/etc/bind/zones/db.lab.local"; };
3. Restart Bind9: systemctl restart bind9
4. Verify:
   nmcli dev status
   nmcli general status
   dig @127.0.0.1 lab.local
   named-checkzone lab.local /etc/bind/zones/db.lab.local
EOS
      ;;
    2)
      cat <<'EOS'
Step-by-step:
1. Create reverse zone file: /etc/bind/zones/db.10.10.20
2. Add zone to /etc/bind/named.conf.local:
   zone "20.10.10.in-addr.arpa" { type master; file "/etc/bind/zones/db.10.10.20"; };
3. Restart Bind9: systemctl restart bind9
4. Verify:
   nmcli dev status
   nmcli general status
   dig @127.0.0.1 -x 10.10.20.11
   named-checkzone 20.10.10.in-addr.arpa /etc/bind/zones/db.10.10.20
EOS
      ;;
    3)
      cat <<'EOS'
Step-by-step:
1. Install dnsmasq: apt-get install -y dnsmasq
2. Configure /etc/dnsmasq.d/lab.conf:
   cache-size=1000
   listen-address=127.0.0.1
3. Restart dnsmasq: systemctl restart dnsmasq
4. Verify:
   nmcli dev status
   nmcli general status
   dig @127.0.0.1 www.lab.local
   systemctl status dnsmasq
EOS
      ;;
    4)
      cat <<'EOS'
Step-by-step:
1. Edit /etc/bind/named.conf.options for split DNS views.
2. Add internal and external views for lab.local.
3. Restart Bind9: systemctl restart bind9
4. Verify:
   nmcli dev status
   nmcli general status
   dig @127.0.0.1 lab.local
   named-checkconf
EOS
      ;;
    5)
      cat <<'EOS'
Step-by-step:
1. Check Bind9 status: systemctl status bind9
2. Check zone files: named-checkzone lab.local /etc/bind/zones/db.lab.local
3. Check DNS resolution: dig @127.0.0.1 lab.local
4. Check reverse DNS: dig @127.0.0.1 -x 10.10.20.11
5. Fix errors in zone files, restart Bind9.
EOS
      ;;
    6)
      cat <<'EOS'
Step-by-step:
1. Install Bind9: apt-get install -y bind9
2. Create zone files in /etc/bind/zones
3. Add zones to /etc/bind/named.conf.local
4. Restart Bind9: systemctl restart bind9
5. Verify:
   nmcli dev status
   nmcli general status
   systemctl status bind9
   netstat -ln | grep :53
   named-checkconf
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
  case "$lab" in
    1) echo "Use named-checkzone to validate zone files before restarting Bind9." ;;
    2) echo "Reverse zones map IPs to names; PTR records are key." ;;
    3) echo "dnsmasq is lightweight and great for caching; check /etc/dnsmasq.d/ for config." ;;
    4) echo "Split DNS lets you serve different answers to internal/external clients." ;;
    5) echo "Use dig and named-checkzone to debug DNS issues; check logs in /var/log/syslog." ;;
    6) echo "Bind9 is the gold standard for local DNS; always validate config with named-checkconf." ;;
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
      3) : > "${STATE_FILE}" 2>/dev/null || true; echo -e "${OK} Reset complete"; read -rp "Press Enter..." ;;
      4) echo -e "${INFO} Current Lab: $(get_state lab || echo '(none)')"; systemctl status bind9 || true; systemctl status dnsmasq || true; read -rp "Press Enter..." ;;
      5) cat <<EOF
${BOLD}Section 4 Labs${NC}
1. Configure Creating Forward Zones
2. Configure Creating Reverse Zones
3. Configure DNS Caching with dnsmasq
4. Configure Split DNS Configuration
5. Troubleshooting DNS
6. Setting Up a Local DNS Server (Bind9)
EOF
         read -rp "Press Enter..." ;;
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
