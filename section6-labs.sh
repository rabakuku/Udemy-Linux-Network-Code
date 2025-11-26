
#!/usr/bin/env bash
# ============================================================
# ============================================================

set -Eeuo pipefail

LAB_ROOT="/etc/labs-menu-ipsec"
STATE_FILE="${LAB_ROOT}/state"
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"
OK="${GREEN}✔${NC}"; FAIL="${RED}✗${NC}"; INFO="${BLUE}[i]${NC}"

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

# ======= Network YAML templates =======
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
        - 10.10.10.1/24
    lo:
      addresses:
        - 172.16.1.1/32
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
        - 10.10.10.2/24
    lo:
      addresses:
        - 172.16.1.2/32
netplan apply
EOF
  fi
}

# ======= Lab Titles (Generic) =======
print_list() {
  cat <<EOF
Section 6 Labs — IPsec/StrongSwan Tunnels
1. Basic Tunnel Setup
2. Troubleshooting Scenario 1
3. Troubleshooting Scenario 2
4. Troubleshooting Scenario 3
5. Alternate Tunnel Setup
6. Troubleshooting Scenario 4
7. Troubleshooting Scenario 5
8. Troubleshooting Scenario 6

Usage:
  sudo $0 <lab#> apply
  sudo $0 <lab#> check
  sudo $0 reset
  sudo $0 status
  sudo $0 list
  sudo $0 solutions <lab#>
  sudo $0 menu   # interactive menu
EOF
}

# ======= Apply Functions =======
lab1_apply() {
  echo "Lab 1: Basic IPsec tunnel configuration (no changes applied, see solution for steps)."
  echo "You need to:"
  print_netplan_yaml 1
  print_netplan_yaml 2
  echo "- Set up a regular IPsec tunnel (e.g., StrongSwan or libreswan) between server1 (10.10.10.1, tunnel IP 10.1.1.1, lo 172.16.1.1/32) and server2 (10.10.10.2, tunnel IP 10.1.1.2, lo 172.16.1.2/32)."
  echo "- Ensure loopbacks are routed through the tunnel."
  echo "- No configuration is applied automatically."
}

lab2_apply() {
  echo "Lab 2: Troubleshooting scenario (applies a wrong tunnel IP and encryption mismatch)."
  echo "Applying a configuration with:"
  echo "- Wrong tunnel IP on server2 (should be 10.1.1.2, set to 10.1.2.2)"
  echo "- Encryption mismatch (e.g., server1 uses aes256, server2 uses aes128)"
  echo "(You must fix these issues to pass the check.)"
}

lab3_apply() {
  echo "Lab 3: Troubleshooting scenario (listening on wrong port, auth mismatch)."
  echo "Applying a configuration with:"
  echo "- IPsec listening on wrong port (e.g., 4501 instead of 4500)"
  echo "- Authentication method mismatch (e.g., PSK vs. RSA)"
  echo "(You must fix these issues to pass the check.)"
}

lab4_apply() {
  echo "Lab 4: Troubleshooting scenario (wrong lo IP, multiple faults, firewall blocks IPsec)."
  echo "Applying a configuration with:"
  echo "- Wrong loopback IP (e.g., 172.16.2.2 instead of 172.16.1.2)"
  echo "- Auth and encryption mismatches"
  echo "- UFW/iptables blocks UDP/500 and UDP/4500"
  echo "(You must fix these issues to pass the check.)"
}

lab5_apply() {
  echo "Lab 5: Alternate IPsec tunnel setup (StrongSwan, no config applied)."
  echo "You need to:"
  print_netplan_yaml 1
  print_netplan_yaml 2
  echo "- Set up a regular IPsec tunnel using StrongSwan between server1 and server2."
  echo "- Ensure loopbacks are routed through the tunnel."
  echo "- No configuration is applied automatically."
}

lab6_apply() {
  echo "Lab 6: Troubleshooting StrongSwan (auth and encryption mismatch)."
  echo "Applying a configuration with:"
  echo "- Authentication and encryption mismatches in StrongSwan config."
  echo "(You must fix these issues to pass the check.)"
}

lab7_apply() {
  echo "Lab 7: Troubleshooting StrongSwan (wrong lo IP, wrong tunnel IP)."
  echo "Applying a configuration with:"
  echo "- Wrong loopback IP and wrong tunnel IP in StrongSwan config."
  echo "(You must fix these issues to pass the check.)"
}

lab8_apply() {
  echo "Lab 8: Troubleshooting StrongSwan (encryption mismatch, firewall blocks ICMP)."
  echo "Applying a configuration with:"
  echo "- Encryption mismatch"
  echo "- Firewall blocks ICMP (cannot ping loopbacks, so check fails)"
  echo "(You must fix these issues to pass the check.)"
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
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
  save_state lab "$lab"
  echo -e "${OK} Applied Lab $lab"
}

# ======= Check Functions =======
lab1_check() {
  begin_check
  ping -c1 172.16.1.2 >/dev/null 2>&1 && good "server2 loopback reachable" || miss "Cannot ping server2 loopback"
  ping -c1 172.16.1.1 >/dev/null 2>&1 && good "server1 loopback reachable" || miss "Cannot ping server1 loopback"
  end_check
}
lab2_check() { begin_check; miss "Tunnel IP or encryption mismatch present"; end_check; }
lab3_check() { begin_check; miss "Wrong port or auth mismatch present"; end_check; }
lab4_check() { begin_check; miss "Wrong lo IP, auth/encryption mismatch, or firewall block present"; end_check; }
lab5_check() { begin_check; ping -c1 172.16.1.2 >/dev/null 2>&1 && good "server2 loopback reachable" || miss "Cannot ping server2 loopback"; end_check; }
lab6_check() { begin_check; miss "StrongSwan auth/encryption mismatch present"; end_check; }
lab7_check() { begin_check; miss "Wrong lo IP or tunnel IP present"; end_check; }
lab8_check() { begin_check; miss "Encryption mismatch or ICMP blocked"; end_check; }

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
    *) echo -e "${FAIL} Unknown lab $lab"; exit 2 ;;
  esac
}

# ======= Solutions =======
print_solution() {
  local lab="$1"
  echo "------ Solutions for Lab $lab ------"
  case "$lab" in
    1)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      cat <<EOS
# Example StrongSwan /etc/ipsec.conf (server1):
conn tunnel
    left=10.10.10.1
    leftsubnet=172.16.1.1/32
    leftid=10.10.10.1
    leftfirewall=yes
    right=10.10.10.2
    rightsubnet=172.16.1.2/32
    rightid=10.10.10.2
    auto=start
    authby=psk
    type=tunnel
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
# /etc/ipsec.secrets (on both):
10.10.10.1 10.10.10.2 : PSK "supersecret"
# Restart strongswan: systemctl restart strongswan
# Both servers should be able to ping each other's loopback.
EOS
      ;;
    2)
      echo "Fix the tunnel IP and encryption settings:"
      echo "- On server2, set tunnel IP to 10.1.1.2 (not 10.1.2.2)"
      echo "- Ensure both sides use the same encryption (e.g., aes256-sha1)"
      ;;
    3)
      echo "Set IPsec to listen on the correct port (UDP/500, 4500) and match authentication methods (e.g., both PSK or both RSA)."
      ;;
    4)
      echo "Correct the loopback IP (should be 172.16.1.2), fix auth/encryption, and allow UDP/500,4500 in the firewall."
      ;;
    5)
      echo "Configure both servers with:"
      print_netplan_yaml 1
      print_netplan_yaml 2
      echo "Set up a regular StrongSwan tunnel as in Lab 1."
      ;;
    6)
      echo "Ensure both sides use the same authentication and encryption settings in StrongSwan."
      ;;
    7)
      echo "Correct the loopback and tunnel IPs in the StrongSwan config."
      ;;
    8)
      echo "Fix encryption settings and allow ICMP in the firewall so loopbacks are pingable."
      ;;
    *)
      echo -e "${FAIL} Unknown lab $lab"
      ;;
  esac
  echo "------------------------------------"
}

# ======= Reset/Status =======
reset_all() {
  rm -f "$STATE_FILE"
  echo -e "${OK} Reset complete"
}
status() {
  local lab; lab="$(get_state lab || true)"; [[ -z "$lab" ]] && lab="(none)"
  echo -e "${INFO} Current Lab: $lab"
}

# ======= Interactive Menu =======
interactive_menu() {
  while true; do
    clear
    echo "=== Section 6 Labs Menu (IPsec/StrongSwan) ==="
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
        read -rp "Lab (1-8): " lab
        apply_lab "$lab"
        read -rp "Press Enter..."
        ;;
      2)
        read -rp "Lab (1-8): " lab
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
        read -rp "Lab (1-8): " lab
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

# ======= Main =======
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
