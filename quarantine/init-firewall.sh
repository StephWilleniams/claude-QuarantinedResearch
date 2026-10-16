#!/bin/bash
# Egress firewall for the research worker.
# Runs as root inside the container, before the worker starts.
# Allows: DNS to the container's resolvers, and HTTPS (tcp/443) to public addresses.
# Blocks: everything else, including loopback-style, private, link-local
# (cloud metadata), carrier-grade NAT, multicast and reserved ranges, and all IPv6.
set -euo pipefail

BLOCKED_V4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"

RESOLVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

iptables -F OUTPUT
iptables -F INPUT
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for r in $RESOLVERS; do
  iptables -A OUTPUT -d "$r" -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$r" -p tcp --dport 53 -j ACCEPT
done
# Loopback is blocked too: nothing in the worker needs it, and it would let a
# fetch of "127.1"-style hosts reach services inside the container.
for net in $BLOCKED_V4; do
  iptables -A OUTPUT -d "$net" -j REJECT
done
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -j REJECT

# IPv6: the launcher disables it with sysctls. Refuse to run if a global IPv6
# address exists anyway and ip6tables cannot lock it down.
has_global_v6() { [ -r /proc/net/if_inet6 ] && awk '$4 == "00" {found=1} END {exit !found}' /proc/net/if_inet6; }
if ip6tables -L >/dev/null 2>&1; then
  ip6tables -F OUTPUT
  ip6tables -F INPUT
  ip6tables -P OUTPUT DROP
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A INPUT -i lo -j ACCEPT
elif has_global_v6; then
  echo "IPv6 is active but cannot be filtered" >&2
  exit 1
fi

# Refuse to continue unless the default-deny policy is really in place.
# The catch-all REJECT must be the last rule. iptables-nft prints it with its
# default "--reject-with icmp-port-unreachable"; iptables-legacy may not.
iptables -S OUTPUT | grep -qx -- '-P OUTPUT DROP' || { echo "firewall policy not active" >&2; exit 1; }
iptables -S OUTPUT | tail -n 1 | grep -qxE -- '-A OUTPUT -j REJECT( --reject-with icmp-port-unreachable)?' \
  || { echo "firewall final reject missing" >&2; exit 1; }
