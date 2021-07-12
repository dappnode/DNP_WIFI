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
#   - docs: https://linux.die.net/man/8/ip  https://access.redhat.com/sites/default/files/attachments/rh_ip_command_cheatsheet_1214_jcs_print.pdf
#   - how to use: https://linuxize.com/post/linux-ip-command/

# iw: tool for wireless devices, substitutes iwconfig
#   - docs: https://wireless.wiki.kernel.org/en/users/documentation/iw  https://linux.die.net/man/8/iw
#   - how to use: # http://ict.siit.tu.ac.th/help/iw

# Other:
#   - networkManager (allow to easily create wifi hostpot on host): https://wiki.debian.org/NetworkManager

# DEBUG: docker run -it --privileged --net=host --pid=host --entrypoint /bin/sh wifi.dnp.dappnode.eth:0.2.7  

# TODO: Resarch on how to sustitute the eth0 wired interface by a wireless interface

# FLOW
# 0. Main services to run on wifi container: dnsmasq && hostapd. 
# 1. Assign default wlan values to variables if does not exist
# 2. Get network interface && check requirements && link to container && up
# 3. Get PHYsical interface && check requirements && link to container && up
# 4. Set rules netns
# 5. If hostapd and dnsmasq files not edited, edit config files and reload services
# 6. Entrypoint waiting forever


########
# VARS #
########

# Colors
YELLOW='\e[0;33m'
MAGENTA='\e[0;35m'
RED='\e[0;31m'
GREEN='\e[0;32m'
BLUE='\e[0;34m'
NC='\e[0m'
ROOT_UID="0"
ARCH=$(arch)

# WLAN parameters
WPA_MODE="WPA-PSK"
SSID="${SSID:=DAppNodeWIFI}"
SUBNET="${SUBNET:=172.33.12.0}"
AP_ADDR="${AP_ADDR:=172.33.12.254}"
DNS_SERVER="${DNS_SERVER:=172.33.1.2}"
NAT="${NAT:=true}"
INTERFACE="${INTERFACE:=}"
CHANNEL="${CHANNEL:=11}"
WPA_PASSPHRASE="${WPA_PASSPHRASE:=dappnode}"                
HW_MODE="${HW_MODE:=g}"
DRIVER="${DRIVER:=nl80211}"
HT_CAPAB="${HT_CAPAB:=[HT40-][SHORT-GI-20]}"
IP_AP="${IP_AP:=nl80211}"
NETMASK="${NETMASK:=/24}"

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

# Get host interface: WARNING! host network interface may disappear for a while and not exist for up to 2 minutes
function get_interface {
    # 1, Get interface
    # iw dev returns empty value if does not exist
    INTERFACE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    while [ -z ${INTERFACE} ]; do
        echo "Waiting for WIFI interface..."
        ((COUNT++)) && ((COUNT==20)) && echo -e "${YELLOW}[WARNING]${NC} No interface found after 120s, stopping gracefully" && exit 0
        sleep 6
        INTERFACE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    done
    echo -e "${BLUE}[INFO]${NC} Interface found: ${INTERFACE}"

    # 2. double-Check interface exists in /sys/class/net/$INTERFACE
    INTERFACE_EXISTS=$(${NSENTER_COMMAND} test -- -d /sys/class/net/${INTERFACE} && echo true || echo false)
    [ ${INTERFACE_EXISTS} == "false" ] && echo -e "${RED}[ERROR]${NC} Interface ${INTERFACE} not detected on the host. Exiting..."
    echo -e "${BLUE}[INFO]${NC} Interface ${INTERFACE} successfully detected on host"
   
    # 3. Check if is in used by the host
    INTERFACE_DEFAULT_HOST=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "ip r" | grep default | cut -d " " -f5)
    # Unblock default network interface, if its in use by the host it may loose internet connection
    [ $INTERFACE == $INTERFACE_DEFAULT_HOST ] && echo -e "${YELLOW}[WARNING]${NC} The selected interface is configured as the default route, attemping to unblock it" && $(${NSENTER_COMMAND} rfkill unblock wifi)
}

# Set up interface in container
function interface_setup {
    echo -e "${BLUE}[INFO]${NC} Starting interface ${INTERFACE}"
    ip link set "$INTERFACE" up
}

# get physical network device from host
function get_phy {
    # Assign name of phy if exists, otherwhise empty value
    PHY_OUTPUT=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/bash ${CONTAINER_IMAGE} -c "test -f /sys/class/net/${INTERFACE}/phy80211/name && cat /sys/class/net/wlan0/phy80211/name || echo ''")
    # Clean PHY_OUTPUT: It may have escape chars \n
    PHY=${PHY_OUTPUT//[$'\t\r\n ']}
    # Exit if PHY is empty
    [ -z "$PHY" ] && echo -e "${RED}[ERROR]${NC} Could not get the phy name at: /sys/class/net/${INTERFACE}/phy80211/name" && exit 1
    echo -e "${BLUE}[INFO]${NC} Physical network device detected: ${PHY}"
}

# Link physical network device to container
function phy_setup {
    # WARNING!: This command will make dissappear the network interface (wlan0) and the network physical device (phy0) from the host
    # phy <phyname> set netns { <pid> | name <nsname> }
		# Put this wireless device into a different network namespace:
		    # <pid>    - change network namespace by process id
		    # <nsname> - change network namespace by name from /run/netns
		               # or by absolute path (man ip-netns)
    docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw phy ${PHY} set netns ${CONTAINER_PID}"
}

# Create hostapd.conf && restart hostapd.service if needed
function hostapd_setup {
    # Create hostapd.conf file ht_capab=${HT_CAPAB}?
    if grep -Fxq "DAPPNODE" /etc/hostapd.conf
        then
            echo -e "${BLUE}[INFO]${NC} hostapd.conf already configured"
        else
            echo -e "${BLUE}[INFO]${NC} Configuring hostapd.conf..."
                cat > "/etc/hostapd/hostapd.conf" <<EOF
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
    # rc-service hostapd start
    fi
    echo -e "${BLUE}[INFO]${NC} Starting hostapd"
    /usr/sbin/hostapd & 
}

# Create dnsmasq.conf && restart dnsmasq.service if needed
function dnsmasq_setup {
    # Create dnsmasq.conf
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
        # rc-service dnsmasq start
    fi
    echo -e "${BLUE}[INFO]${NC} Starting dnsmasq"
    /usr/sbin/dnsmasq & wait ${!} 
}

function ip_forward {
    # IP forwarding
    echo "Enabling ip_dynaddr, ip_forward"
    for i in ip_dynaddr ip_forward ; do 
        if [ $(cat /proc/sys/net/ipv4/$i) ]; then
            echo -e "${BLUE}[INFO]${NC} $i already 1"
            echo $i already 1 
        else
            echo "1" > /proc/sys/net/ipv4/$i
        fi
    done
}

function service_start {
    ip addr flush dev ${INTERFACE}
    ip addr add ${AP_ADDR}${NETMASK} dev ${INTERFACE}
    iptables -t nat -A POSTROUTING -s ${SUBNET}.0${NETMASK} ! -d ${SUBNET}.0${NETMASK} -j MASQUERADE
    ip_forward

    # If needed: edit and reload hostapd and dnsmasq
    hostapd_setup
    dnsmasq_setup
}

function service_stop {
    # Remove ip address
    docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "ip addr del ${AP_ADDR}${NETMASK} dev ${INTERFACE} > /dev/null 2>&1"
}

###########
# HANDLER #
###########

sigterm_handler () {
  echo -e "${BLUE}[INFO]${NC} Caught singal. Stopping wifi service gracefully"
  service_stop
  #clear
  exit 0
}

trap 'sigterm_handler' TERM INT
 
########
# MAIN #
########

print_banner
get_interface
get_phy
phy_setup
interface_setup
service_start