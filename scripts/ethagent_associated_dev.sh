#!/bin/sh

UTOPIA_PATH="/etc/utopia/service.d"
LOG_FILE="/rdklogs/logs/EthAgentSelfHeal.log"

SERVICE="CcspEthAgent"
DMCLI="dmcli eRT getv"
ETH_API="/usr/bin/eth_api CcspHalExtSw_getAssociatedDevice"
LOG_PREFIX="[EthAgentSelfHeal]"

# Ensure log directory exists
mkdir -p /rdklogs/logs

# Source RDK logger
source $UTOPIA_PATH/log_capture_path.sh

# Redirect ALL stdout/stderr of this script to our log file
exec >> "$LOG_FILE" 2>&1

log() {
    echo_t "$LOG_PREFIX $*"
}

# -----------------------
# Get eth_wan mode
# -----------------------
get_ethwan_mode() {
    ETH_WAN_ENABLED=$(syscfg get eth_wan_enabled 2>/dev/null)
    if [ "$ETH_WAN_ENABLED" = "true" ]; then
        IF_LIST="1 2 3"
    else
        IF_LIST="1 2 3 4"
    fi
    log "eth_wan_enabled=$ETH_WAN_ENABLED"
    log "Checking interfaces: $IF_LIST"
}

# ---------------------------------------------------------
# Sum AssociatedDeviceNumberOfEntries for all interfaces
# ---------------------------------------------------------
get_dmcli_sum() {
    SUM=0
    DMCLI_VALUES=""
    for IFNUM in $IF_LIST; do
        VALUE=$($DMCLI Device.Ethernet.Interface.${IFNUM}.X_RDKCENTRAL-COM_AssociatedDeviceNumberOfEntries \
            2>/dev/null | awk '/value:/ {print $NF}')
        VALUE=${VALUE:-0}
        DMCLI_VALUES="$DMCLI_VALUES IF$IFNUM:$VALUE"
        SUM=$((SUM + VALUE))
    done
    log "DMCLI interface counts:$DMCLI_VALUES"
    log "Total associated devices (DMCLI sum): $SUM"
}

# ---------------------------------
# Get eth_api total eth dev count
# ---------------------------------
get_total_eth() {
    TOTAL_ETH=$($ETH_API 2>/dev/null | awk '/Total_ETH:/ {print $2}')
    TOTAL_ETH=${TOTAL_ETH:-0}
    log "Total_ETH from eth_api: $TOTAL_ETH"
}

# -----------------------
# Get CcspEthAgent PID
# -----------------------
get_service_pid() {
    PID=$(pidof "$SERVICE")
    log "$SERVICE PID: ${PID:-Not running}"
}

# -------------------------------
# Restart eth agent process
# -------------------------------
restart_service() {
    log "Restarting $SERVICE..."
    systemctl restart "$SERVICE"

    if [ $? -eq 0 ]; then
        log "$SERVICE restarted successfully"
        # Give it a second to settle
        sleep 1
        get_service_pid
    else
        log "ERROR: Failed to restart $SERVICE"
    fi
}

# ----------------------------------
# Main compare and trigger restart
# ----------------------------------
log "===== EthAgent selfheal check started ====="

get_ethwan_mode

# Capture values before restart
get_dmcli_sum
DMCLI_SUM_BEFORE=$SUM
get_total_eth
TOTAL_ETH_BEFORE=$TOTAL_ETH
get_service_pid
PID_BEFORE=$PID

# Compare counts
if [ "$DMCLI_SUM_BEFORE" -eq 0 ] && [ "$TOTAL_ETH_BEFORE" -ne 0 ]; then
    log "Mismatch detected (DMCLI_SUM=$DMCLI_SUM_BEFORE, Total_ETH=$TOTAL_ETH_BEFORE)"
    restart_service

    log "Sleep 10 secs after restart..."
    sleep 10

    # Capture values after restart
    get_dmcli_sum
    DMCLI_SUM_AFTER=$SUM
    get_total_eth
    TOTAL_ETH_AFTER=$TOTAL_ETH
    log "After restart - DMCLI_SUM=$DMCLI_SUM_AFTER, Total_ETH=$TOTAL_ETH_AFTER"
else
    log "Counts match. No action required."
fi

log "===== EthAgent selfheal check completed ====="
exit 0

