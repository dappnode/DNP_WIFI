#!/bin/bash -e

# Check if running in privileged mode
if [ ! -w "/sys" ] ; then
    echo "[Error] Not running in privileged mode."
    exit 1
fi

# Default values
true ${SUBNET:=172.33.12.0}
true ${AP_ADDR:=172.33.12.254}
true ${DNS:=172.33.1.2}
true ${NAT:=true}
true ${INTERFACE:=}
true ${SSID:=DAppNodeWIFI}
true ${CHANNEL:=11}
true ${WPA_PASSPHRASE:=dappnode}
true ${HW_MODE:=g}
true ${DRIVER:=nl80211}
true ${HT_CAPAB:=[HT40-][SHORT-GI-20]}

CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ${HOSTNAME})
CONTAINER_IMAGE=$(docker inspect -f '{{.Config.Image}}' ${HOSTNAME})
if [ -z ${INTERFACE} ]; then
  INTERFACE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw dev" | grep 'Interface' | awk 'NR==1{print $2}')
fi

# We have seen cases in which after an update it is not able to obtain the interface
# it may be because the previous container has not had time to release the interface
# This adds a one minute wait before stopping for not finding an interface
while [ -z ${INTERFACE} ]
do
    echo "Waiting for WIFI interface..."
    ((COUNT++)) && ((COUNT==10)) && echo "[Warning] No interface found after 60s, stopping gracefully" && exit 0
    sleep 6
done

# Not all the WIFI drivers are compatilbe with [SHORT-GI-20] (e.g., RaspberryPi 4)
# So we need to check it before add it
CHECK_CAPAB=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "iw list" | grep -q 'short GI for 40 MHz' && echo '[SHORT-GI-20]' || echo '' )
HT_CAPAB="${HT_CAPAB}${CHECK_CAPAB}"

echo "Attaching interface ${INTERFACE} to container"
IFACE_OPSTATE=$(docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "cat /sys/class/net/${INTERFACE}/operstate")
if [ ${IFACE_OPSTATE::-1} = "down" ]; then
  docker run -t --privileged --net=host --pid=host --rm --entrypoint /bin/sh ${CONTAINER_IMAGE} -c "
    PHY=\$(echo phy\$(iw dev ${INTERFACE} info | grep wiphy | tr ' ' '\n' | tail -n 1))
    iw phy \$PHY set netns ${CONTAINER_PID}"
  ip link set ${INTERFACE} name wlan0
  INTERFACE=wlan0
else
  echo "[Warning] Interface ${INTERFACE} already connected. WIFI hotspot cannot be initialized since the host machine is using it"
  exit 0
fi

if [ ! -f "/etc/hostapd.conf" ]; then
    cat > "/etc/hostapd.conf" <<EOF
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
ht_capab=${HT_CAPAB}
wmm_enabled=1
EOF

fi

# unblock wlan
rfkill unblock wlan

echo "Setting interface ${INTERFACE}"

# Setup interface and restart DHCP service 
ip link set ${INTERFACE} up
ip addr flush dev ${INTERFACE}
ip addr add ${AP_ADDR}/24 dev ${INTERFACE}

# IP forwarding
echo "Enabling ip_dynaddr, ip_forward"
for i in ip_dynaddr ip_forward ; do 
  if [ $(cat /proc/sys/net/ipv4/$i) ]; then
    echo $i already 1 
  else
    echo "1" > /proc/sys/net/ipv4/$i
  fi
done

cat /proc/sys/net/ipv4/ip_dynaddr 
cat /proc/sys/net/ipv4/ip_forward

# Wihout NAT: Proxy ARP mode
if [ $NAT != 'true' ]; then
  echo "Enablig Proxy ARP"
  echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp
fi

if [ "${OUTGOINGS}" ] ; then
   ints="$(sed 's/,\+/ /g' <<<"${OUTGOINGS}")"
   for int in ${ints}
   do
      echo "Setting iptables for outgoing traffics on ${int}..."
      iptables -t nat -D POSTROUTING -s ${SUBNET}/24 -o ${int} -j MASQUERADE > /dev/null 2>&1 || true
      iptables -t nat -A POSTROUTING -s ${SUBNET}/24 -o ${int} -j MASQUERADE
   done
elif [ $NAT = 'true' ]; then
   echo "Setting iptables for outgoing traffics on all interfaces..."
   iptables -t nat -D POSTROUTING -s ${SUBNET}/24 -j MASQUERADE > /dev/null 2>&1 || true
   iptables -t nat -A POSTROUTING -s ${SUBNET}/24 -j MASQUERADE
fi

echo "Configuring DHCP server .."
cat > "/etc/dhcp/dhcpd.conf" <<EOF
option domain-name-servers ${DNS};
option subnet-mask 255.255.255.0;
option routers ${AP_ADDR};
subnet ${SUBNET} netmask 255.255.255.0 {
  range ${SUBNET::-1}100 ${SUBNET::-1}253;
}
EOF

echo "Starting DHCP server .." 
dhcpd ${INTERFACE}

echo "Starting HostAP daemon ..."
cat /etc/hostapd.conf
/usr/sbin/hostapd /etc/hostapd.conf