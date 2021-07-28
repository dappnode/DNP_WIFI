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
#HT_CAPAB="${HT_CAPAB:=[HT40-][SHORT-GI-20]}"

# Docker
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ${HOSTNAME})
CONTAINER_IMAGE=$(docker inspect -f '{{.Config.Image}}' ${HOSTNAME})
CONTAINER_COMMAND="docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c"

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
    # 1, Get interface name from host
    INTERFACE=$(${CONTAINER_COMMAND} "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    while [ -z ${INTERFACE} ]; do
        echo "Waiting for WIFI interface..."
        ((COUNT++)) && ((COUNT==20)) && echo -e "${YELLOW}[WARNING]${NC} No interface found after 120s, stopping gracefully" && exit 0
        sleep 6
        # iw dev returns empty value if interface not present
        INTERFACE=$(${CONTAINER_COMMAND} "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
    done
    echo -e "${BLUE}[INFO]${NC} Interface found: ${INTERFACE}"

    # 2. Double check interface exists on host
    INTERFACE_EXISTS=$(${CONTAINER_COMMAND} "test -- -d /sys/class/net/${INTERFACE} && echo true || echo false")
    [ "$INTERFACE_EXISTS" == "false" ] && echo -e "${RED}[ERROR]${NC} Interface ${INTERFACE} not detected on the host"
    echo -e "${BLUE}[INFO]${NC} Interface ${INTERFACE} successfully detected on host"
   
    # 3. Check if interface blocked
    # Example output:
    # 0: phy0: wlan
	#    Soft blocked: yes
	#    Hard blocked: no

    INTERFACE_BLOCKED=$(${CONTAINER_COMMAND} "rfkill list wlan")
    # "Soft blocked" means "blocked by software"
    INTERFACE_SOFT_BLOCKED=$(echo "${INTERFACE_BLOCKED}" | grep -i soft | grep -i yes 1> /dev/null && echo "blocked" || echo "unblocked" )
    # "Hard blocked" cannot be changed by software, may need a reboot
    INTERFACE_HARD_BLOCKED=$(echo "${INTERFACE_BLOCKED}" | grep -i hard | grep -i yes 1> /dev/null && echo "blocked" || echo "unblocked" )
    # Exit if interface hard blocked
    [ "$INTERFACE_HARD_BLOCKED" == "blocked" ] && echo -e "${RED}[ERROR]${NC} The selected interface is hard blocked on the host, a reboot may be necessary. Stopping gracefully" && exit 0
    # Unblock default network interface, if its in use by the host it may loose internet connection
    [ "$INTERFACE_SOFT_BLOCKED" == "blocked" ] && echo -e "${YELLOW}[WARNING]${NC} The selected interface is soft blocked on the host, attemping to unblock it..." && $(${CONTAINER_COMMAND} "rfkill unblock wifi")
}

# Set up interface in container
function interface_setup {
    echo -e "${BLUE}[INFO]${NC} Starting interface ${INTERFACE}"
    ip link set "$INTERFACE" up
}

# get physical network device from host
function get_phy {
    # Assign name of phy if exists, otherwhise empty value
    PHY_OUTPUT=$(${CONTAINER_COMMAND} "test -f /sys/class/net/${INTERFACE}/phy80211/name && cat /sys/class/net/${INTERFACE}/phy80211/name || echo ''")
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
    echo -e "${BLUE}[INFO]${NC} Attaching physical network device ${PHY} to container pid"
    # If in compose does not share namespace with host
    docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw phy ${PHY} set netns ${CONTAINER_PID}"
}

# Create hostapd.conf
function hostapd_setup {
    # Create hostapd.conf file ht_capab=${HT_CAPAB}?
    if grep -Fxq "DAPPNODE" /etc/hostapd/hostapd.conf
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
}

# Create dnsmasq.conf
function dnsmasq_setup {
    # Create dnsmasq.conf
    if grep -Fxq "DAPPNODE" /etc/dnsmasq.conf
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
dhcp-range=${SUBNET::-1}100,${SUBNET::-1}253,255.255.255.0,12h
EOF
        # rc-service dnsmasq start
    fi
}

# IP forwarding
function ip_forward {
    for i in ip_dynaddr ip_forward ; do 
        if [ $(cat /proc/sys/net/ipv4/$i) ]; then
            echo -e "${BLUE}[INFO]${NC} $i already 1"
        else
            echo "1" > /proc/sys/net/ipv4/$i
        fi
    done
}

# Configure IP settings (address, subnet, ip forwarding, ip tables)
function ip_setup {
    echo -e "${BLUE}[INFO]${NC} Removing addresses from interface ${INTERFACE}"
    ip addr flush dev "${INTERFACE}"
    echo -e "${BLUE}[INFO]${NC} Attaching wifi address to interface ${INTERFACE}"
    ip addr add "${AP_ADDR}/24" dev "${INTERFACE}"
    echo -e "${BLUE}[INFO]${NC} Enabling ip_dynaddr, ip_forward"
    ip_forward
    echo -e "${BLUE}[INFO]${NC} Generating ip tables for subnet ${SUBNET}"
    iptables -t nat -A POSTROUTING -s "${SUBNET}/24" ! -d "${SUBNET}/24" -j MASQUERADE
}

# Execute binaries for hostapd and dnsmasq, do not change the current order of execution. Another approach would be to use them as services and execute them on startup (check Dockerfile comment)
function service_start {
    # Setup config files
    hostapd_setup
    dnsmasq_setup
    # Start process in bacground and wait
    echo -e "${BLUE}[INFO]${NC} Starting dnsmasq"
    dnsmasq & 
    echo -e "${BLUE}[INFO]${NC} Starting hostapd"
    hostapd /etc/hostapd/hostapd.conf & wait ${!} 
}

function service_stop {
    echo -e "${BLUE}[INFO]${NC} Removing wifi IP address from ${INTERFACE}..."
    ip addr del ${AP_ADDR}/24 dev ${INTERFACE} > /dev/null 2>&1

    echo -e "${BLUE}[INFO]${NC} Switching down ${INTERFACE}..."
    ip link set "$INTERFACE" down

    echo -e "${BLUE}[INFO]${NC} Killing daemons hostapd and dnsmasq..."
    pkill hostapd
    pkill dnsmasq

    # If in compose share namespace with host then set interface from the container back to the host. pid: "host"
    echo -e "${BLUE}[INFO]${NC} Attaching interface ${PHY} from container to host"
    iw phy ${PHY} set netns 1
}

###########
# HANDLER #
###########

sigterm_handler () {
  echo -e "${BLUE}[INFO]${NC} Caught singal. Stopping wifi service gracefully"
  service_stop
  clear
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
ip_setup
service_start