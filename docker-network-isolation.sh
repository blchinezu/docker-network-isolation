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

# ============================================================
# Common variables
# ============================================================
COMPOSE_FILE="docker-compose.yaml"

# Dynamically detect the Docker network name from docker-compose.yaml
COMPOSE_NETWORK=$(awk '/^networks:/{found=1; next} found && /^  [a-zA-Z_-]/{gsub(/:.*/, ""); gsub(/^[[:space:]]+/, ""); print; exit}' "$COMPOSE_FILE" 2>/dev/null)
if [ -z "$COMPOSE_NETWORK" ]; then
    COMPOSE_NETWORK="default"
fi
NETWORK_NAME=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep "_${COMPOSE_NETWORK}$" | head -1)
if [ -z "$NETWORK_NAME" ]; then
    echo "Error: Docker network '*_${COMPOSE_NETWORK}' not found. Make sure docker-compose is running."
    exit 1
fi

# Dynamically detect the subnet from docker-compose.yaml, fallback to live Docker network
SUBNET=""
if [ -f "$COMPOSE_FILE" ] && [ ! -z "$COMPOSE_NETWORK" ]; then
    SUBNET=$(awk -v net="$COMPOSE_NETWORK" '
        /^networks:/{f=1; next}
        f && $0 ~ "^  "net":"{g=1; next}
        g && /^  [a-zA-Z_-]/{exit}
        g && /subnet:/{gsub(/.*subnet:[[:space:]]*/, ""); print; exit}
    ' "$COMPOSE_FILE")
fi
if [ -z "$SUBNET" ]; then
    SUBNET=$(docker network inspect "$NETWORK_NAME" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
fi
if [ -z "$SUBNET" ]; then
    echo "Warning: Could not determine subnet from docker-compose.yaml or live Docker network."
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
        echo "Error: docker-compose.yaml not found at $COMPOSE_FILE"
        exit 1
    elif [[ "$ACTION" != "unblock" ]]; then
        echo "Warning: docker-compose.yaml not found."
    fi
fi
CONTAINER_PORTS=("${!CONTAINER_PORTS_MAP[@]}")

if [[ "$ACTION" == "block-lan" && ${#CONTAINER_PORTS[@]} -eq 0 ]]; then
    echo "Error: No port mappings found in docker-compose.yaml"
    exit 1
fi

if [[ ${#CONTAINER_PORTS[@]} -gt 0 ]]; then
    echo "Detected container ports from docker-compose.yaml:"
    for cp in "${CONTAINER_PORTS[@]}"; do
        echo "  - $cp"
    done
    echo ""
fi

# ============================================================
# Resolve Docker network interface
# ============================================================
NETWORK_ID=$(docker network inspect $NETWORK_NAME -f '{{.Id}}' 2>/dev/null)

if [ -z "$NETWORK_ID" ]; then
    echo "Error: Network $NETWORK_NAME not found. Make sure docker-compose is running."
    exit 1
else
    INTERFACE="br-${NETWORK_ID:0:12}"
fi

# ============================================================
# Detect current network isolation status
# ============================================================
detect_status() {
    local docker_user_rules
    docker_user_rules=$(sudo iptables -S DOCKER-USER 2>/dev/null)

    # Check for blanket REJECT (present in block-internet and block-all)
    local blanket_reject
    blanket_reject=$(echo "$docker_user_rules" | grep -c -- "-i $INTERFACE -j REJECT")

    # Check for private network RETURN rules (present in block-internet only)
    local private_return
    private_return=$(echo "$docker_user_rules" | grep -c -- "-i $INTERFACE -d 192.168.0.0/16 -j RETURN")

    # Check for private network REJECT NEW rules (present in block-lan only)
    local private_reject_new
    private_reject_new=$(echo "$docker_user_rules" | grep -c -- "-i $INTERFACE -d 192.168.0.0/16 -m conntrack --ctstate NEW -j REJECT")

    if [[ $blanket_reject -gt 0 && $private_return -gt 0 ]]; then
        echo "blocked-internet"
    elif [[ $blanket_reject -gt 0 && $private_return -eq 0 ]]; then
        echo "blocked-all"
    elif [[ $private_reject_new -gt 0 ]]; then
        echo "blocked-lan"
    else
        echo "unblocked"
    fi
}

# ============================================================
# Resolve host LAN IP
# ============================================================
DEFAULT_IFACE=$(ip route | grep default | grep -oP 'dev \K\S+' | head -1)
if [ ! -z "$DEFAULT_IFACE" ]; then
    HOST_LAN_IP=$(ip addr show $DEFAULT_IFACE | grep 'inet ' | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
fi

if [[ "$ACTION" == "block-lan" && -z "$HOST_LAN_IP" ]]; then
    echo "Error: Could not determine the host's LAN IP address."
    exit 1
fi

echo "Network: $NETWORK_NAME"
echo "Interface: $INTERFACE"
echo "Subnet: $SUBNET"
echo "Host LAN IP: ${HOST_LAN_IP:-unknown}"
echo ""

# ============================================================
# UNBLOCK - Remove all isolation rules from any mode
# ============================================================
do_unblock() {
    local quiet="$1"

    # --- DOCKER-USER chain: block-internet / block-all rules ---
    sudo iptables -D DOCKER-USER -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER ESTABLISHED/RELATED RETURN rule"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 10.0.0.0/8 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 10.0.0.0/8"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 172.16.0.0/12 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 172.16.0.0/12"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 192.168.0.0/16 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 192.168.0.0/16"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 169.254.0.0/16 -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER RETURN rule for 169.254.0.0/16"
    sudo iptables -D DOCKER-USER -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed DOCKER-USER REJECT-all rule"

    # --- DOCKER-USER chain: block-lan rules ---
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 192.168.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 192.168.0.0/16"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 10.0.0.0/8 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 10.0.0.0/8"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 172.16.0.0/12 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 172.16.0.0/12"
    sudo iptables -D DOCKER-USER -i $INTERFACE -d 169.254.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed block-lan rule for 169.254.0.0/16"

    # Docker subnet (clean up both old REJECT and new RETURN rules)
    local live_subnet=$(docker network inspect $NETWORK_NAME -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
    if [ ! -z "$live_subnet" ]; then
        sudo iptables -D DOCKER-USER -i $INTERFACE -d $live_subnet -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed REJECT rule for Docker subnet ($live_subnet)"
        sudo iptables -D DOCKER-USER -i $INTERFACE -d $live_subnet -j RETURN 2>/dev/null && [ -z "$quiet" ] && echo "Removed RETURN rule for Docker subnet ($live_subnet)"
    fi

    # Host LAN IP rules (block-lan per-port rules)
    if [ ! -z "$HOST_LAN_IP" ]; then
        sudo iptables -D DOCKER-USER -i $INTERFACE -d $HOST_LAN_IP -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed REJECT rule for host LAN IP ($HOST_LAN_IP)"
        for cp in "${CONTAINER_PORTS[@]}"; do
            port="${cp%%/*}"
            proto="${cp#*/}"
            sudo iptables -D DOCKER-USER -i $INTERFACE -d $HOST_LAN_IP -p $proto --sport $port -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && [ -z "$quiet" ] && echo "Removed ACCEPT for $proto port $port"
        done
    fi

    # --- INPUT chain (shared by block-lan and block-all) ---
    sudo iptables -D INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable 2>/dev/null && [ -z "$quiet" ] && echo "Removed INPUT REJECT rule"
    sudo iptables -D INPUT -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && [ -z "$quiet" ] && echo "Removed INPUT ACCEPT ESTABLISHED/RELATED rule"
}

# ============================================================
# BLOCK-INTERNET - Block internet, allow LAN/host
# ============================================================
do_block_internet() {
    do_unblock quiet

    echo "Applying internet blocking rules..."
    echo ""

    local pos=1

    # Allow ESTABLISHED/RELATED (for responses to port-forwarded connections)
    echo "Adding RETURN for ESTABLISHED/RELATED traffic..."
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN; ((pos++))

    # Allow private network ranges (LAN access)
    echo "Adding RETURN for private network ranges (allow LAN)..."
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -d 10.0.0.0/8 -j RETURN; ((pos++))
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -d 172.16.0.0/12 -j RETURN; ((pos++))
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -d 192.168.0.0/16 -j RETURN; ((pos++))
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -d 169.254.0.0/16 -j RETURN; ((pos++))

    # Block everything else (internet)
    echo "Adding REJECT rule for all other traffic (internet)..."
    sudo iptables -I DOCKER-USER $pos -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

    echo ""
    echo "Internet blocking enabled!"
    echo "VM can access LAN/host but cannot access the internet."
    echo ""
    echo "To remove these rules, run: $0 unblock"
}

# ============================================================
# BLOCK-LAN - Block LAN/host, allow internet
# ============================================================
do_block_lan() {
    do_unblock quiet

    echo "Applying LAN blocking rules..."
    echo ""

    # --- DOCKER-USER chain (FORWARD) ---

    # Allow ESTABLISHED/RELATED for each mapped container port
    for cp in "${CONTAINER_PORTS[@]}"; do
        port="${cp%%/*}"
        proto="${cp#*/}"
        echo "Adding ACCEPT for ESTABLISHED/RELATED $proto from container port $port..."
        sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d $HOST_LAN_IP -p $proto --sport $port -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done

    # Block everything else to the host LAN IP
    POSITION=$((${#CONTAINER_PORTS[@]} + 1))
    echo "Adding REJECT rule for all other traffic to host LAN IP ($HOST_LAN_IP)..."
    sudo iptables -I DOCKER-USER $POSITION -i $INTERFACE -d $HOST_LAN_IP -j REJECT --reject-with icmp-host-unreachable

    # Block NEW outgoing connections to private networks (LAN + other Docker networks)
    echo "Adding REJECT rules for private network ranges..."
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d 192.168.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d 10.0.0.0/8 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d 172.16.0.0/12 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d 169.254.0.0/16 -m conntrack --ctstate NEW -j REJECT --reject-with icmp-host-unreachable

    # Allow intra-compose communication (own Docker subnet) - inserted last so it's evaluated first
    echo "Adding RETURN rule for own Docker subnet ($SUBNET) to allow intra-compose traffic..."
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -d $SUBNET -j RETURN

    # --- INPUT chain (container -> host direct) ---
    echo "Adding INPUT chain rules to block container -> host access..."
    sudo iptables -I INPUT 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

    echo ""
    echo "LAN blocking enabled!"
    echo "Containers can communicate within the same compose project."
    echo "Cannot access LAN, host, or other Docker compose networks."
    echo "Internet access is allowed."
    echo ""
    echo "To remove these rules, run: $0 unblock"
}

# ============================================================
# BLOCK-ALL - Block both internet and LAN/host
# ============================================================
do_block_all() {
    do_unblock quiet

    echo "Applying full network blocking rules..."
    echo ""

    # --- DOCKER-USER chain ---

    # Allow ESTABLISHED/RELATED (for responses to port-forwarded connections)
    echo "Adding RETURN for ESTABLISHED/RELATED traffic..."
    sudo iptables -I DOCKER-USER 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    # Allow intra-compose communication (own Docker subnet)
    echo "Adding RETURN rule for own Docker subnet ($SUBNET) to allow intra-compose traffic..."
    sudo iptables -I DOCKER-USER 2 -i $INTERFACE -d $SUBNET -j RETURN

    # Block everything else (internet + LAN + other Docker networks)
    echo "Adding REJECT rule for all other traffic..."
    sudo iptables -I DOCKER-USER 3 -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

    # --- INPUT chain (container -> host direct) ---
    echo "Adding INPUT chain rules to block container -> host access..."
    sudo iptables -I INPUT 1 -i $INTERFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A INPUT -i $INTERFACE -j REJECT --reject-with icmp-host-unreachable

    echo ""
    echo "Full network blocking enabled!"
    echo "Containers can communicate within the same compose project."
    echo "Cannot access internet, LAN, host, or other Docker compose networks."
    echo "Can still respond to port-forwarded connections."
    echo ""
    echo "To remove these rules, run: $0 unblock"
}

# ============================================================
# Run
# ============================================================
CURRENT_STATUS=$(detect_status)

case "$ACTION" in
    block-internet)
        if [[ "$CURRENT_STATUS" == "blocked-internet" ]]; then
            echo "Mode 'block-internet' is already active. Nothing to do."
        else
            do_block_internet
        fi
        ;;
    block-lan)
        if [[ "$CURRENT_STATUS" == "blocked-lan" ]]; then
            echo "Mode 'block-lan' is already active. Nothing to do."
        else
            do_block_lan
        fi
        ;;
    block-all)
        if [[ "$CURRENT_STATUS" == "blocked-all" ]]; then
            echo "Mode 'block-all' is already active. Nothing to do."
        else
            do_block_all
        fi
        ;;
    unblock)
        if [[ "$CURRENT_STATUS" == "unblocked" ]]; then
            echo "Network is already unblocked. Nothing to do."
        else
            echo "Removing all network isolation rules..."
            echo ""
            do_unblock
            echo ""
            echo "All network isolation rules removed!"
        fi
        ;;
    status)
        case "$CURRENT_STATUS" in
            blocked-internet) echo "Current status: blocked-internet (internet blocked, LAN/host allowed)" ;;
            blocked-lan)      echo "Current status: blocked-lan (LAN/host blocked, internet allowed)" ;;
            blocked-all)      echo "Current status: blocked-all (internet and LAN/host blocked)" ;;
            unblocked)        echo "Current status: unblocked (no isolation rules active)" ;;
        esac
        ;;
esac

