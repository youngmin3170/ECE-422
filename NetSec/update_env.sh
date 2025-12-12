#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# update VM files
cp "${SCRIPTPATH}/update_files/netsec-setup" /usr/local/bin/netsec-setup
cp "${SCRIPTPATH}/update_files/netsec-start" /usr/local/bin/netsec-start
cp "${SCRIPTPATH}/update_files/netsec-stop" /usr/local/bin/netsec-stop
cp "${SCRIPTPATH}/update_files/netsec-destroy" /usr/local/bin/netsec-destroy
cp "${SCRIPTPATH}/update_files/config.xml" /srv/netsec/netbsd/config.xml
cp "${SCRIPTPATH}/update_files/update-iptables.sh" /srv/common/update-iptables.sh

echo "NetSec environment update completed"
