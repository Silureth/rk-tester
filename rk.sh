#!/bin/bash

set -u

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
TMP_JIRA="/tmp/jira_check_$$"

IOC_IP_REGEX='45\.79\.33\.42|185\.117\.74\.172|94\.125\.182\.255|45\.58\.183\.18|199\.71\.214\.87'

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

section "HOST"
echo "Hostname: $HOSTNAME_FQDN"
uname -a
echo
echo "Uptime:"
uptime 2>/dev/null || true

section "JIRA PATH HIDING TEST"

touch "$TMP_JIRA" 2>/dev/null

if [ -e "$TMP_JIRA" ]; then
    echo "PASS: lowercase 'jira' path is visible"
    rm -f "$TMP_JIRA"
else
    echo "ALERT: lowercase 'jira' path was created but is not visible"
    echo "       This matches the path-hiding behavior seen on isziir."
fi

section "LD.SO.PRELOAD"

if [ -e /etc/ld.so.preload ]; then
    ls -la /etc/ld.so.preload
    lsattr /etc/ld.so.preload 2>/dev/null || true
    echo
    cat /etc/ld.so.preload 2>/dev/null
else
    echo "PASS: /etc/ld.so.preload does not exist"
fi

echo
echo "Related preload files:"
ls -la /etc/ld.so.preload* 2>/dev/null || true

section "KNOWN MALICIOUS FILE IOCS"

for f in \
    /usr/local/lib/libproc.so \
    /usr/local/lib/libproc-2.8.so \
    /usr/local/lib/libaudit.so \
    /usr/sbin/postgresq1
do
    if [ -e "$f" ]; then
        echo "ALERT: found $f"
        ls -la "$f"
        lsattr "$f" 2>/dev/null || true
        sha256sum "$f" 2>/dev/null || true
    fi
done

section "KNOWN SYSTEMD IOCS"

systemctl list-unit-files --type=service 2>/dev/null \
    | grep -Ei 'systemct1|open-tls' || true

find \
    /etc/systemd \
    /usr/lib/systemd \
    /lib/systemd \
    -type f \
    \( -name 'systemct1.service' -o -name 'open-tls.service' \) \
    -ls 2>/dev/null

section "CPAN CACHE / CRON IOCS"

echo "-- cron references --"

grep -RnaE '\.cpan/.cache/update|postgresq1|systemct1|open-tls' \
    /etc/cron.d \
    /etc/cron.daily \
    /etc/cron.hourly \
    /etc/cron.weekly \
    /etc/cron.monthly \
    /var/spool/cron \
    2>/dev/null || true

echo
echo "-- suspicious update payload paths --"

find \
    /home \
    /root \
    /usr/local/games \
    -path '*/.cpan/.cache/update' \
    -ls 2>/dev/null

section "PACKAGEKIT / CVE-2026-41651"

if dpkg-query -W packagekit >/dev/null 2>&1; then
    PKGVER="$(dpkg-query -W -f='${Version}' packagekit 2>/dev/null)"

    echo "PackageKit installed: $PKGVER"

    echo
    echo "Package repository information:"
    apt-cache policy packagekit 2>/dev/null || true

    echo
    echo "NOTE:"
    echo "Package version alone is only a heuristic."
    echo "Debian/Ubuntu may backport a security fix without changing"
    echo "the upstream-looking version number."

else
    echo "PASS: PackageKit not installed"
fi

echo
echo "-- PackageKit exploit-style artifacts --"

find /tmp /var/tmp /dev/shm \
    \( \
        -name 'pkbuild*' \
        -o -name 'pk-dummy*' \
        -o -name 'pk-payload*' \
        -o -path '*/DEBIAN/postinst' \
        -o -path '*/DEBIAN/preinst' \
    \) \
    -ls 2>/dev/null

echo
echo "-- PackageKit journal indicators --"

journalctl --no-pager 2>/dev/null \
    | grep -Ei \
      'pkbuild|pk-dummy|pk-payload|packagekit' \
    | tail -100 || true

section "FTRACE / KERNEL HOOK CHECK"

TRACEFILE="/sys/kernel/debug/tracing/enabled_functions"

if [ ! -r "$TRACEFILE" ]; then
    if [ -d /sys/kernel/debug ]; then
        mountpoint -q /sys/kernel/debug || \
            mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi
fi

if [ -r "$TRACEFILE" ]; then
    COUNT="$(wc -l < "$TRACEFILE" 2>/dev/null)"

    echo "Enabled ftrace functions: $COUNT"

    if [ "${COUNT:-0}" -gt 50 ] 2>/dev/null; then
        echo "WARNING: unusually large number of enabled ftrace functions"
    fi

    echo
    echo "-- first 50 hooks --"
    head -50 "$TRACEFILE"

    echo
    echo "-- security-sensitive hooked functions --"

    grep -Ei \
      'find_module|__module_address|kallsyms|kill|signal|getdents|readdir|stat|open|audit|bpf|socket|connect|tcp|udp|proc|syslog' \
      "$TRACEFILE" \
      | head -100 || true
else
    echo "INFO: enabled_functions unavailable"
fi

section "KERNEL MODULE / TAINT"

echo -n "Kernel taint: "
cat /proc/sys/kernel/tainted 2>/dev/null || echo "unknown"

echo
echo "-- loaded modules --"
lsmod 2>/dev/null | head -100 || true

section "NETWORK IOCS"

echo "-- active TCP connections matching known IOC IPs or :6667 --"

ss -ntp 2>/dev/null \
    | grep -E ":6667|$IOC_IP_REGEX" \
    || echo "No matching active TCP connections"

echo
echo "-- active UDP connections matching IOC IPs --"

ss -nup 2>/dev/null \
    | grep -E "$IOC_IP_REGEX" \
    || echo "No matching active UDP connections"

section "RECENT JOURNAL IOC SEARCH"

journalctl --since "-30 days" --no-pager 2>/dev/null \
    | grep -Ei \
      'postgresq1|systemct1|open-tls|pk-payload|pk-dummy|pkbuild|\.cpan/.cache/update' \
    | tail -200 || true

section "SUMMARY"

echo "Strong indicators:"
echo "  - 'jira' path hidden"
echo "  - /usr/sbin/postgresq1 exists"
echo "  - systemct1.service exists"
echo "  - open-tls.service exists"
echo "  - /usr/local/lib/libproc*.so exists"
echo "  - /usr/local/lib/libaudit.so exists"
echo "  - .cpan/.cache/update persistence"
echo "  - repeated connections to TCP/6667"
echo "  - known IOC destination IPs"
echo
echo "Supporting indicators:"
echo "  - PackageKit exploit artifacts such as pkbuild/pk-payload"
echo "  - large unexplained ftrace hook set"
echo "  - suspicious DEBIAN/postinst files under temporary directories"
echo
echo "Absence of these indicators does NOT prove the host is clean."