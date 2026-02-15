#!/bin/bash

# Script to control network isolation modes for Docker containers
# Run after starting docker-compose

# ============================================================
# Usage
# ============================================================
usage() {
  echo "Usage: $0 {block-internet|block-lan|block-all|unblock|status}"
  echo ""
  echo "  block-internet  - Block internet access, allow LAN/host"
  echo "  block-lan       - Block LAN/host access, allow internet"
  echo "  block-all       - Block both internet and LAN/host access"
  echo "  unblock         - Remove all isolation rules"
  echo "  status          - Show current network isolation state"
  exit 1
}

ACTION="$1"
if [[ "$ACTION" != "block-internet" && "$ACTION" != "block-lan" && "$ACTION" != "block-all" && "$ACTION" != "unblock" && "$ACTION" != "status" ]]; then
  usage
fi

CURRENT_DIR_NAME=$(basename $(pwd))

# ============================================================
# Output verbosity
# ============================================================
ECHO_MODE=2 # verbose
if [ "$2" == "--minimal-output" ]; then
  ECHO_MODE=1
elif [ "$2" == "--silent" ]; then
  ECHO_MODE=0
fi

function echoAlways() {
  echo "[$CURRENT_DIR_NAME] $@"
}
function echoMinimal() {
  if [ $ECHO_MODE -ge 1 ]; then
    echo "[$CURRENT_DIR_NAME] $@"
  fi
}
function echoVerbose() {
  if [ $ECHO_MODE -ge 2 ]; then
    echo "[$CURRENT_DIR_NAME] $@"
  fi
}

# ============================================================
# Check for docker-compose file existence
# ============================================================
COMPOSE_FILE=""
if [ -f "docker-compose.yaml" ]; then
  COMPOSE_FILE="docker-compose.yaml"
elif [ -f "docker-compose.yml" ]; then
  COMPOSE_FILE="docker-compose.yml"
else
  echoAlways "[ERROR] No docker-compose.yaml or docker-compose.yml found in current directory."
  exit 1
fi

# ============================================================
# Check for network configuration in docker-compose file
# ============================================================
if ! grep -q "^networks:" "$COMPOSE_FILE"; then
  echoAlways "[ERROR] No network configuration found in $COMPOSE_FILE."
  exit 1
fi

# ============================================================
# Common variables
# ============================================================

# Dynamically detect the Docker network name from docker-compose.yaml
COMPOSE_NETWORK=$(awk '/^networks:/{found=1; next} found && /^  [a-zA-Z_-]/{gsub(/:.*/, ""); gsub(/^[ \t]+/, ""); print; exit}' "$COMPOSE_FILE" 2>/dev/null)
if [ -z "$COMPOSE_NETWORK" ]; then
  COMPOSE_NETWORK="default"
fi
NETWORK_NAME=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep "_${COMPOSE_NETWORK}$" | head -1)
if [ -z "$NETWORK_NAME" ]; then
  echoAlways "[ERROR] Docker network '*_${COMPOSE_NETWORK}' not found. Make sure docker-compose is running."
  exit 1
fi

# Dynamically detect the subnet from docker-compose.yaml, fallback to live Docker network
SUBNET=""
if [ -f "$COMPOSE_FILE" ] && [ ! -z "$COMPOSE_NETWORK" ]; then
  SUBNET=$(awk -v net="$COMPOSE_NETWORK" '
    /^networks:/{f=1; next}
    f && $0 ~ "^  "net":"{g=1; next}
    g && /^  [a-zA-Z_-]/{exit}
    g && /subnet:/{gsub(/.*subnet:[ \t]*/, ""); print; exit}
  ' "$COMPOSE_FILE")
fi
if [ -z "$SUBNET" ]; then
  SUBNET=$(docker network inspect "$NETWORK_NAME" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
fi
if [ -z "$SUBNET" ]; then
  echoAlways "[WARN] Could not determine subnet from docker-compose.yaml or live Docker network."
fi

# ============================================================
# Parse container ports from docker-compose.yaml
# ============================================================
declare -A CONTAINER_PORTS_MAP
if [ -f "$COMPOSE_FILE" ]; then
  PORT_LINES=$(grep -P '^\s+-\s+\d+:\d+' "$COMPOSE_FILE" | grep -oP '\d+:\d+(/\w+)?')
  while IFS= read -r mapping; do
    [ -z "$mapping" ] && continue
    container_part="${mapping#*:}"
    container_port="${container_part%%/*}"
    if [[ "$container_part" == */* ]]; then
      protocol="${container_part#*/}"
    else
      protocol="tcp"
    fi
    CONTAINER_PORTS_MAP["$container_port/$protocol"]=1
  done <<< "$PORT_LINES"
else
  if [[ "$ACTION" == "block-lan" ]]; then
    echoAlways "[ERROR] docker-compose.yaml not found at $COMPOSE_FILE"
    exit 1
  elif [[ "$ACTION" != "unblock" ]]; then
    echoAlways "[WARN] docker-compose.yaml not found."
  fi
fi
CONTAINER_PORTS=("${!CONTAINER_PORTS_MAP[@]}")

if [[ ${#CONTAINER_PORTS[@]} -gt 0 ]]; then
  echoVerbose "Detected container ports from docker-compose.yaml:"
  for cp in "${CONTAINER_PORTS[@]}"; do
    echoVerbose "  - $cp"
  done
  echoVerbose ""
fi

# ============================================================
# Resolve Docker network interface
# ============================================================
NETWORK_ID=$(docker network inspect $NETWORK_NAME -f '{{.Id}}' 2>/dev/null)

if [ -z "$NETWORK_ID" ]; then
  echoAlways "[ERROR] Network $NETWORK_NAME not found. Make sure docker-compose is running."
  exit 1
else
  INTERFACE="br-${NETWORK_ID:0:12}"
fi

# ============================================================
# Detect current network isolation status
# ============================================================
detect_status() {
  local docker_user_rules
  docker_user_rules=$(cat ~/tmp/.stf | sudo -S iptables -S DOCKER-USER 2>/dev/null)

  # Note: iptables-nft may reorder options (e.g. -d before -i), so we use
  # piped greps to check for each part independently of order.

  # Private network REJECT NEW rules are unique to block-lan
  if echo "$docker_user_rules" | grep -- "-i $INTERFACE" | grep -- "-d 192.168.0.0/16" | grep -- "--ctstate NEW" | grep -q -- "-j REJECT"; then
    echo "blocked-lan"
    return
  fi

  # Private network RETURN rules are unique to block-internet
  if echo "$docker_user_rules" | grep -- "-i $INTERFACE" | grep -- "-d 192.168.0.0/16" | grep -q -- "-j RETURN"; then
    echo "blocked-internet"
    return
  fi

  # Blanket REJECT (no -d qualifier) without private RETURN means block-all
  if echo "$docker_user_rules" | grep -- "-i $INTERFACE" | grep -- "-j REJECT" | grep -qv -- " -d "; then
    echo "blocked-all"
    return
  fi

  echo "unblocked"
}

# ============================================================
# Resolve host LAN IP
# ============================================================
DEFAULT_IFACE=$(ip route | grep default | grep -oP 'dev \K\S+' | head -1)
if [ ! -z "$DEFAULT_IFACE" ]; then
  HOST_LAN_IP=$(ip addr show $DEFAULT_IFACE | grep 'inet ' | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
fi

if [[ "$ACTION" == "block-lan" && -z "$HOST_LAN_IP" ]]; then
  echoAlways "[ERROR] Could not determine the host's LAN IP address."
  exit 1
fi

echoVerbose "Network: $NETWORK_NAME"
echoVerbose "Interface: $INTERFACE"
echoVerbose "Subnet: $SUBNET"
echoVerbose "Host LAN IP: ${HOST_LAN_IP:-unknown}"
echoVerbose ""

# ============================================================
# UNBLOCK - Remove all isolation rules from any mode
# ============================================================
do_unblock() {
  local quiet="$1"

  if [ "$quiet" != "quiet" ]; then
    echoVerbose "Removing all network isolation rules..."
    echoVerbose ""
  fi

  # --- DOCKER-USER chain: block-internet / block-all rules ---
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER ESTABLISHED/RELATED RETURN rule"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 10.0.0.0/8 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 10.0.0.0/8"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 172.16.0.0/12 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 172.16.0.0/12"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 192.168.0.0/16 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 192.168.0.0/16"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 169.254.0.0/16 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 169.254.0.0/16"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER REJECT-all rule"

  # --- DOCKER-USER chain: block-lan rules ---
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 192.168.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 192.168.0.0/16"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 10.0.0.0/8 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 10.0.0.0/8"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 172.16.0.0/12 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 172.16.0.0/12"
  cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d 169.254.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 169.254.0.0/16"

  # Docker subnet (clean up both old REJECT and new RETURN rules)
  local live_subnet=$(docker network inspect $NETWORK_NAME -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
  if [ ! -z "$live_subnet" ]; then
    cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d $live_subnet -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed REJECT rule for Docker subnet ($live_subnet)"
    cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d $live_subnet -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed RETURN rule for Docker subnet ($live_subnet)"
  fi

  # Host LAN IP rules (block-lan per-port rules)
  if [ ! -z "$HOST_LAN_IP" ]; then
    cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d $HOST_LAN_IP -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed REJECT rule for host LAN IP ($HOST_LAN_IP)"
    for cp in "${CONTAINER_PORTS[@]}"; do
      port="${cp%%/*}"
      proto="${cp#*/}"
      cat ~/tmp/.stf | sudo -S iptables -D DOCKER-USER -i $INTERFACE -d $HOST_LAN_IP -p $proto --sport $port -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && [ -z "$quiet" ] && echo "Removed ACCEPT for $proto port $port"
    done
  fi

  # --- INPUT chain (shared by block-lan and block-all) ---
  cat ~/tmp/.stf | sudo -S iptables -D INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed INPUT REJECT rule"
  cat ~/tmp/.stf | sudo -S iptables -D INPUT -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && [ -z "$quiet" ] && echo "Removed INPUT ACCEPT ESTABLISHED/RELATED rule"
  if [ "$quiet" != "quiet" ]; then
    echoVerbose ""
    echoMinimal "All network isolation rules removed!"
  fi
}

# ============================================================
# BLOCK-INTERNET - Block internet, allow LAN/host
# ============================================================
do_block_internet() {
  do_unblock quiet

  echoVerbose "Applying internet blocking rules..."
  echoVerbose ""

  local pos=1

  # Allow ESTABLISHED/RELATED (for responses to port-forwarded connections)
  echoVerbose "Adding RETURN for ESTABLISHED/RELATED traffic..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN; ((pos++))

  # Allow private network ranges (LAN access)
  echoVerbose "Adding RETURN for private network ranges (allow LAN)..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -d 10.0.0.0/8 -j RETURN; ((pos++))
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -d 172.16.0.0/12 -j RETURN; ((pos++))
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -d 192.168.0.0/16 -j RETURN; ((pos++))
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -d 169.254.0.0/16 -j RETURN; ((pos++))

  # Block everything else (internet)
  echoVerbose "Adding REJECT rule for all other traffic (internet)..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $pos -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

  echoVerbose ""
  echoMinimal "Internet blocking enabled!"
  echoVerbose "VM can access LAN/host but cannot access the internet."
}

# ============================================================
# BLOCK-LAN - Block LAN/host, allow internet
# ============================================================
do_block_lan() {
  do_unblock quiet

  echoVerbose "Applying LAN blocking rules..."
  echoVerbose ""

  # --- DOCKER-USER chain (FORWARD) ---

  # Allow ESTABLISHED/RELATED for each mapped container port
  for cp in "${CONTAINER_PORTS[@]}"; do
    port="${cp%%/*}"
    proto="${cp#*/}"
    echoVerbose "Adding ACCEPT for ESTABLISHED/RELATED $proto from container port $port..."
    cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d $HOST_LAN_IP -p $proto --sport $port -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  # Block everything else to the host LAN IP
  POSITION=$((${#CONTAINER_PORTS[@]} + 1))
  echoVerbose "Adding REJECT rule for all other traffic to host LAN IP ($HOST_LAN_IP)..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER $POSITION -i $INTERFACE -d $HOST_LAN_IP -j REJECT --reject-with icmp-host-unreachable

  # Block NEW outgoing connections to private networks (LAN + other Docker networks)
  echoVerbose "Adding REJECT rules for private network ranges..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d 192.168.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d 10.0.0.0/8 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d 172.16.0.0/12 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d 169.254.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable

  # Allow intra-compose communication (own Docker subnet) - inserted last so it's evaluated first
  echoVerbose "Adding RETURN rule for own Docker subnet ($SUBNET) to allow intra-compose traffic..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -d $SUBNET -j RETURN

  # --- INPUT chain (container -> host direct) ---
  echoVerbose "Adding INPUT chain rules to block container -> host access..."
  cat ~/tmp/.stf | sudo -S iptables -I INPUT 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  cat ~/tmp/.stf | sudo -S iptables -A INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

  echoVerbose ""
  echoMinimal "LAN blocking enabled!"
  echoVerbose "Containers can communicate within the same compose project."
  echoVerbose "Cannot access LAN, host, or other Docker compose networks."
  echoVerbose "Internet access is allowed."
}

# ============================================================
# BLOCK-ALL - Block both internet and LAN/host
# ============================================================
do_block_all() {
  do_unblock quiet

  echoVerbose "Applying full network blocking rules..."
  echoVerbose ""

  # --- DOCKER-USER chain ---

  # Allow ESTABLISHED/RELATED (for responses to port-forwarded connections)
  echoVerbose "Adding RETURN for ESTABLISHED/RELATED traffic..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

  # Allow intra-compose communication (own Docker subnet)
  echoVerbose "Adding RETURN rule for own Docker subnet ($SUBNET) to allow intra-compose traffic..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 2 -i $INTERFACE -d $SUBNET -j RETURN

  # Block everything else (internet + LAN + other Docker networks)
  echoVerbose "Adding REJECT rule for all other traffic..."
  cat ~/tmp/.stf | sudo -S iptables -I DOCKER-USER 3 -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

  # --- INPUT chain (container -> host direct) ---
  echoVerbose "Adding INPUT chain rules to block container -> host access..."
  cat ~/tmp/.stf | sudo -S iptables -I INPUT 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  cat ~/tmp/.stf | sudo -S iptables -A INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

  echoVerbose ""
  echoMinimal "Full network blocking enabled!"
  echoVerbose "Containers can communicate within the same compose project."
  echoVerbose "Cannot access internet, LAN, host, or other Docker compose networks."
  echoVerbose "Can still respond to port-forwarded connections."
}

# ============================================================
# Run
# ============================================================
CURRENT_STATUS=$(detect_status)

case "$ACTION" in
  block-internet)
    if [[ "$CURRENT_STATUS" == "blocked-internet" ]]; then
      echoMinimal "'block-internet' is already active"
    else
      do_block_internet
    fi
    ;;
  block-lan)
    if [[ "$CURRENT_STATUS" == "blocked-lan" ]]; then
      echoMinimal "'block-lan' is already active"
    else
      do_block_lan
    fi
    ;;
  block-all)
    if [[ "$CURRENT_STATUS" == "blocked-all" ]]; then
      echoMinimal "'block-all' is already active"
    else
      do_block_all
    fi
    ;;
  unblock)
    if [[ "$CURRENT_STATUS" == "unblocked" ]]; then
      echoMinimal "'unblock' is already active"
    else
      do_unblock
    fi
    ;;
  status)
    if [ $ECHO_MODE -ge 2 ]; then
      case "$CURRENT_STATUS" in
        blocked-internet) echoVerbose "Current status: blocked-internet (internet blocked, LAN/host allowed)" ;;
        blocked-lan)      echoVerbose "Current status: blocked-lan (LAN/host blocked, internet allowed)" ;;
        blocked-all)      echoVerbose "Current status: blocked-all (internet and LAN/host blocked)" ;;
        unblocked)        echoVerbose "Current status: unblocked (no isolation rules active)" ;;
      esac
    else
      echoAlways "$CURRENT_STATUS"
    fi
    ;;
esac
