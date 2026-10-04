#!/bin/bash
# Reachability checks for a client that may only reach the Internet through the proxy.
# Runs inside the client container; feed it from the host:
#   podman exec -i CLIENT bash < tests/integration/proxytest.sh
# Prints one line per check, it does not pass or fail: rc=0 means reachable,
# curl rc 6 = DNS failed, rc 7 = could not connect.
# PROXYTEST_LAN is an address on your LAN that must stay unreachable.
LAN=${PROXYTEST_LAN:-192.168.15.1}
c() { printf '%-42s ' "$1"; shift; out=$(timeout 8 "$@" 2>&1); rc=$?; echo "rc=$rc  $(echo "$out" | tail -1 | cut -c1-70)"; }
echo "interfaces: $(awk -F: 'NR>2{printf "%s ", $1}' /proc/net/dev)   default route: $(awk '$2=="00000000"{print "yes"}' /proc/net/route | head -1)"
c "DNS proxy"                     getent hosts proxy
c "DNS example.com"               getent hosts example.com
c "curl https://example.com"      curl -sS -o /dev/null -w '%{http_code}' https://example.com
c "curl https://1.1.1.1 (by IP)"  curl -sS -o /dev/null -w '%{http_code}' https://1.1.1.1
c "curl LAN $LAN"                 curl -sS -o /dev/null -w '%{http_code}' "http://$LAN"
c "curl host.containers.internal" curl -sS -o /dev/null -w '%{http_code}' http://host.containers.internal:631
c "curl http://proxy:8080"        curl -sS -o /dev/null -w '%{http_code}' http://proxy:8080
c "curl https://api.anthropic.com" curl -sS -o /dev/null -w '%{http_code}' https://api.anthropic.com
