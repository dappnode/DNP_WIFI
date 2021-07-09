#!/bin/bash

# Examples AP:
#   - Debian AP with hostapd: https://www.cyberciti.biz/faq/debian-ubuntu-linux-setting-wireless-access-point/
#   - https://github.com/fgg89/docker-ap/blob/master/docker_ap
#   - https://fwhibbit.es/en/automatic-access-point-with-docker-and-raspberry-pi-zero-w

# Debian network
#   - Wifi interfaces: https://wiki.debian.org/WiFi/HowToUse
#   - List interfaces: https://www.cyberciti.biz/faq/linux-list-network-cards-command/
#   - /network/interfaces: 
#       - names: https://wiki.debian.org/NetworkInterfaceNames
#       - configuration: https://wiki.debian.org/NetworkConfiguration

# hostapd: is a user space daemon for access point and authentication servers. It can be used to create a wireless hotspot using a Linux computer. It implements IEEE 802.11 access point management,
#   - example file: https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
#   - docs: https://wiki.debian.org/hostap

# ip: toolf for wired devices. Substitutes ifconfig
#   - docs: https://linux.die.net/man/8/ip
#   - how to use: https://linuxize.com/post/linux-ip-command/

# iw: tool for wireless devices, substitutes iwconfig
#   - docs: https://wireless.wiki.kernel.org/en/users/documentation/iw  https://linux.die.net/man/8/iw
#   - how to use: # http://ict.siit.tu.ac.th/help/iw

# Other:
#   - networkManager (allow to easily create wifi hostpot on host): https://wiki.debian.org/NetworkManager

# LEARNING
#   - 

# DEBUG: docker run -it --privileged --net=host --pid=host --entrypoint /bin/sh wifi.dnp.dappnode.eth:0.2.7  

# The current flow is: the wifi container uses the eth0 interface which is routed to a network interface to create the wifi hostpor
# Resarch on how to sustitute the eth0 wired interface by a wireless interface

# ROADMAP
# 0. Start entrypoint with services start: dnsmasq && hostapd 
# 1. Assign default wlan values to variables if does not exist
# 2. Get wireless interface name
# 3. Check: wireless interface available && not in use by the host
# 4. Get PHYsical interface for the wireless interface
# 3. Unblock wifi && bring the wireless interface up
# 4. Edit hostapd.conf && Edit dnmasq.conf?
# 5. Start hostapd and 

########
# VARS #
########

# Colors
YELLOW'\e[0;33m'
MAGENTA='\e[0;35m'
RED='\e[0;31m'
GREEN='\e[0;32m'
BLUE='\e[0;34m'
NC='\e[0m'
ROOT_UID="0"
ARCH=$(arch)

# WLAN parameters
WPA_MODE="WPA-PSK"
SUBNET="${SUBNET:=172.33.12.0}"
AP_ADDR="${AP_ADDR:=172.33.12.254}"
DNS="${DNS:=172.33.1.2}"
NAT="${NAT:=true}"
INTERFACE="${INTERFACE:=}"                                  X             
CHANNEL="${CHANNEL:=11}"                            X
PASSPHRASE="${PASSPHRASE:=dappnode}"                X
HW_MODE="${HW_MODE:=g}"                             X
DRIVER="${DRIVER:=nl80211}"
HT_CAPAB="${HT_CAPAB:=[HT40-][SHORT-GI-20]}"

# Other parameters
SUBNET="192.168.7"
IP_AP="192.168.7.1"
NETMASK="/24"
DNS_SERVER="8.8.8.8"

# Docker
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ${HOSTNAME})
CONTAINER_IMAGE=$(docker inspect -f '{{.Config.Image}}' ${HOSTNAME})
NSENTER_COMMAND="docker run --rm --privileged --pid=host -t alpine:3.8 nsenter -t 1 -m -u -n -i"

################
# REQUIREMENTS #
################

# Check run as root
if [ "$UID" -ne "$ROOT_UID" ] ; then
    echo "You must be root to run this script!"
    exit 1
fi

# Actions to take if arch is arm?

#############
# FUNCTIONS #
#############

# DAppNode banner
print_banner () {
    echo -e "${MAGENTA} ___   _             _  _         _          _   ___   ${NC}"
    echo -e "${MAGENTA}|   \ /_\  _ __ _ __| \| |___  __| |___     /_\ | _ \\ ${NC}"
    echo -e "${MAGENTA}| |) / _ \| '_ \ '_ \ .  / _ \/ _  / -_)   / _ \|  _/  ${NC}"
    echo -e "${MAGENTA}|___/_/ \_\ .__/ .__/_|\_\___/\__,_\___|  /_/ \_\_|    ${NC}"
    echo -e "${MAGENTA}          |_|  |_|                                     ${NC}"
    echo ""
}

# Get host interface
function get_interface {
    # host network interface may disappear for a while and not exist for up to 2 minutes
    # iw dev returns empty value if does not exist
    INTERFACE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    while [ -z ${INTERFACE} ]; do
        echo "Waiting for WIFI interface..."
        ((COUNT++)) && ((COUNT==20)) && echo -e "${YELLOW}[WARNING]${NC} No interface found after 120s, stopping gracefully" && exit 0
        sleep 6
        INTERFACE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    done
    echo -e "${BLUE}[INFO]${NC} Interface found: ${INTERFACE}"
}


# Check that the interface exists and its not in use. Returns interface phy
function interface_setup {
    # get interface, otherwise exit
    get_interface

    # Check interface exists in /sys/class/net/$INTERFACE
    INTERFACE_EXISTS=$(${NSENTER_COMMAND} test -- -d /sys/class/net/${INTERFACE} && echo true || echo false)
    [ ${INTERFACE_EXISTS} == "false" ] && echo -e "${RED}[ERROR]${NC} Interface ${INTERFACE} not detected on the host. Exiting..." && exit 1

    echo -e "${BLUE}[INFO]${NC} Interface ${INTERFACE} successfully detected on host"
   
    # Get default interface used by the host
    INTERFACE_DEFAULT_HOST=$(${NSENTER_COMMAND} ip r | grep default | cut -d " " -f5)

    # Unblock default network interface, if its in use by the host it may loose internet connection
    [ $INTERFACE == $INTERFACE_DEFAULT_HOST ] && echo -e "${BLUE}[INFO]${NC} The selected interface is configured as the default route, attemping to unblock it" && ${NSENTER_COMMAND} rfkill unblock wifi
    echo -e "${BLUE}[INFO]${NC} Starting interface ${INTERFACE}"
    ip link set "$INTERFACE" up
}

function get_phy {
    # Assign name of phy if exists, otherwhise empty value
    PHY=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "test -f /sys/class/net/${INTERFACE}/phy80211/name && cat /sys/class/net/wlan0/phy80211/name || echo ''")
    # Exit if PHY is empty
    [ -z "$PHY" ] && echo -e "${RED}[ERROR]${NC} Could not get the phy name at: /sys/class/net/${INTERFACE}/phy80211/name" && exit 1
    echo -e "${BLUE}[INFO]${NC} Physical network device detected: ${PHY}"
}

function service_start {
    # 1. Assign phy wireless interface to the container 
    # 2. Assign an IP to the wifi interface
    # 3. iptables rules for NAT
    # 4. Enable IP forwarding
    docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "
        iw phy ${PHY} set netns ${CONTAINER_PID} 
        ip netns exec ${CONTAINER_PID} ip addr flush dev ${INTERFACE}
        ip netns exec ${CONTAINER_PID} ip link set ${INTERFACE} up
        ip netns exec ${CONTAINER_PID} ip addr add ${IP_AP}${NETMASK} dev ${INTERFACE}
        ip netns exec ${CONTAINER_PID} ip addr flush dev ${INTERFACE}
        ip netns exec ${CONTAINER_PID} ip link set ${INTERFACE} up
        ip netns exec ${CONTAINER_PID} ip addr add ${IP_AP$NETMASK} dev ${INTERFACE}
        ip netns exec ${CONTAINER_PID} iptables -t nat -A POSTROUTING -s ${SUBNET}.0${NETMASK} ! -d ${SUBNET}.0${NETMASK} -j MASQUERADE
        ip netns exec ${CONTAINER_PID} echo 1 > /proc/sys/net/ipv4/ip_forward"
}

function hostapd_setup {
    # Create hostapd.conf file ht_capab=${HT_CAPAB}?
    if grep -Fxq "DAPPNODE" my_list.txt
        then
            echo -e "${BLUE}[INFO]${NC} hostapd.conf already configured"
        else
            echo -e "${BLUE}[INFO]${NC} Configuring hostapd.conf..."
                cat > "/etc/hostapd.conf" <<EOF
# DAPPNODE
interface=${INTERFACE}
driver=${DRIVER}
ssid=${SSID}
hw_mode=${HW_MODE}
channel=${CHANNEL}
wpa=2
wpa_passphrase=${WPA_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_ptk_rekey=600
ieee80211n=1
wmm_enabled=1
EOF
    rc-service hostapd restart
    fi
    
}

function dnsmasq_setup {
    # Create hostapd.conf file ht_capab=${HT_CAPAB}?
    if grep -Fxq "DAPPNODE" my_list.txt
        then
            echo -e "${BLUE}[INFO]${NC} dnsmasq.conf already configured"
        else
            echo -e "${BLUE}[INFO]${NC} Configuring dnsmasq.conf..."
                cat > "/etc/dnsmasq.conf" <<EOF
# DAPPNODE
no-resolv 
server=${DNS_SERVER}
interface=lo,${INTERFACE}
no-dhcp-interface=lo
dhcp-range=${SUBNET}.20,${SUBNET}.254,255.255.255.0,12h
EOF
        rc-service dnsmasq restart
    fi
}

###########
# HANDLER #
###########

# STOP CONTAINER:
pid=0

sigterm_handler () {
  echo -e "[*] Caught SIGTERM/SIGINT!"
    if [[ -z "$2" ]]; then
        echo -e "${RED}[ERROR]${NC} No interface found. Exiting..."
        exit 1
    fi
    IFACE=${2}
    service_stop "$IFACE"
    clear
  exit 0
}

trap 'sigterm_handler' TERM INT

# 1. get interface
# 2. get phy
# 3. unblock wifi
# 4. link iface up
# 