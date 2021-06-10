FROM alpine

RUN apk add --no-cache bash hostapd iptables dhcp docker iproute2 iw
RUN echo "" > /var/lib/dhcp/dhcpd.leases
COPY ./*.sh /bin/
RUN chmod +x /bin/wlanstart.sh && \
    chmod +x /bin/iptables.sh && \
    chmod +x /bin/iptables_off.sh 

ENTRYPOINT [ "/bin/wlanstart.sh" ]
