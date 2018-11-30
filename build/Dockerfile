FROM alpine

RUN apk add --no-cache bash hostapd iptables dhcp docker iproute2 iw
RUN echo "" > /var/lib/dhcp/dhcpd.leases
ADD wlanstart.sh /bin/wlanstart.sh
RUN chmod +x /bin/wlanstart.sh

ENTRYPOINT [ "/bin/wlanstart.sh" ]
