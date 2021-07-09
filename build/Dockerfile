FROM alpine

# Update the repos
RUN apk update && apk upgrade -y
# Install libraries
RUN apk add --no-cache -y hostapd dnsmasq bash bridge-utils iw rfkill ip openrc
# Make hostapd and dnsmasq to run on startup
RUN rc-update add hostapd && rc-update add dnsmasq
# Entrypoint executable
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod u+x /usr/bin/entrypoint.sh

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]