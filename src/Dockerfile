ARG BASE_IMAGE=alpine:3.23.7
FROM ${BASE_IMAGE}

# Update the repos
RUN apk update && apk upgrade
# Install libraries
RUN apk add --no-cache 'ca-certificates>=20261020' 'ca-certificates-bundle>=20261020' hostapd dnsmasq bash iw openrc docker iproute2 iptables

# Make hostapd and dnsmasq to run on startup
# RUN rc-update add hostapd && rc-update add dnsmasq

# Entrypoint executable
COPY entrypoint.sh /usr/bin/entrypoint.sh
COPY network.sh /usr/bin/network.sh
RUN chmod u+x /usr/bin/entrypoint.sh

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]
