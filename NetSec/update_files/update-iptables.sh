#!/bin/bash
# check if root
if [ "$EUID" -ne 0 ]; then
    echo "please run as root"
    exit 1
fi

WORKING_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# remove previous rules
OLD_API_IP="$(cat ${WORKING_DIR}/current-github-api-ip)"
iptables -D OUTPUT -d ${OLD_API_IP}/32 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -D OUTPUT -d ${OLD_API_IP}/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -D OUTPUT -d ${OLD_API_IP}/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -D OUTPUT -d ${OLD_API_IP}/32 -p icmp --icmp-type echo-request -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

OLD_IP="$(cat ${WORKING_DIR}/current-github-ip)"
while IFS= read -r subnet; do
    iptables -D OUTPUT -d ${subnet} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -D OUTPUT -d ${subnet} -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -D OUTPUT -d ${subnet} -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
done <<< "$OLD_IP"

# add rules for new IPs
NEW_API_IP="$(dig api.github.com +short | tail -1)"
iptables -A OUTPUT -d ${NEW_API_IP}/32 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d ${NEW_API_IP}/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d ${NEW_API_IP}/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d ${NEW_API_IP}/32 -p icmp --icmp-type echo-request -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
echo "${NEW_API_IP}" > ${WORKING_DIR}/current-github-api-ip

NEW_IP="$(curl -s https://api.github.com/meta | python3 -c 'import json; import sys; meta = json.load(sys.stdin); subnets = [*meta["api"],*meta["git"],*meta["web"]]; subnets = [i for i in subnets if ":" not in i]; uq_subnets = set(subnets); print("\n".join(sorted(uq_subnets)))')"
while IFS= read -r subnet; do
    iptables -A OUTPUT -d ${subnet} -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -d ${subnet} -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -d ${subnet} -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
done <<< "$NEW_IP"
echo "${NEW_IP}" > ${WORKING_DIR}/current-github-ip