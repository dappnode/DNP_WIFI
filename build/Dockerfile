FROM alpine

# Update the repos
RUN apk update && apk upgrade
# Install libraries
RUN apk add --no-cache hostapd dnsmasq bash bridge-utils iw openrc
# Make hostapd and dnsmasq to run on startup
RUN rc-update add hostapd && rc-update add dnsmasq
# Entrypoint executable
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod u+x /usr/bin/entrypoint.sh

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]