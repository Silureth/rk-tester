#!/bin/bash

set -u

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
TMP_JIRA="/tmp/jira_check_$$"

IOC_IP_REGEX='45\.79\.33\.42|185\.117\.74\.172|94\.125\.182\.255|45\.58\.183\.18|199\.71\.214\.87'

RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
RESET='\033[0m'

CRITICAL=0
WARNING=0
INFO=0

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

critical() {
    echo -e "${RED}ALERT: $*${RESET}"
    CRITICAL=$((CRITICAL + 1))
}

warning() {
    echo -e "${YELLOW}WARNING: $*${RESET}"
    WARNING=$((WARNING + 1))
}

info() {
    echo -e "${CYAN}INFO: $*${RESET}"
    INFO=$((INFO + 1))
}

pass() {
    echo -e "${GREEN}PASS: $*${RESET}"
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
    pass "lowercase 'jira' path is visible"
    rm -f "$TMP_JIRA"
else
    critical "lowercase 'jira' path was created but is hidden"
    echo "This matches the path-hiding behavior seen on isziir."
fi


section "LD.SO.PRELOAD"

if [ -e /etc/ld.so.preload ]; then
    warning "/etc/ld.so.preload exists"

    ls -la /etc/ld.so.preload
    lsattr /etc/ld.so.preload 2>/dev/null || true

    echo
    echo "Contents:"
    cat /etc/ld.so.preload 2>/dev/null || true

    if grep -Eq \
        '/usr/local/lib/libproc(-2\.8)?\.so|/usr/local/lib/libaudit\.so' \
        /etc/ld.so.preload 2>/dev/null
    then
        critical "known malicious preload library reference found"
    fi
else
    pass "/etc/ld.so.preload does not exist"
fi

echo
echo "Related preload files:"
ls -la /etc/ld.so.preload* 2>/dev/null || true


section "KNOWN MALICIOUS FILE IOCS"

IOC_FOUND=0

for f in \
    /usr/local/lib/libproc.so \
    /usr/local/lib/libproc-2.8.so \
    /usr/local/lib/libaudit.so \
    /usr/sbin/postgresq1
do
    if [ -e "$f" ]; then
        critical "known IOC file found: $f"
        IOC_FOUND=1

        ls -la "$f"
        lsattr "$f" 2>/dev/null || true
        sha256sum "$f" 2>/dev/null || true
        echo
    fi
done

if [ "$IOC_FOUND" -eq 0 ]; then
    pass "no known malicious files found"
fi


section "KNOWN SYSTEMD IOCS"

SYSTEMD_IOC=0

for unit in systemct1.service open-tls.service; do
    if systemctl list-unit-files --type=service 2>/dev/null \
        | grep -q "^${unit}[[:space:]]"
    then
        critical "known malicious service found: $unit"
        SYSTEMD_IOC=1
    fi
done

find \
    /etc/systemd \
    /usr/lib/systemd \
    /lib/systemd \
    -type f \
    \( -name 'systemct1.service' -o -name 'open-tls.service' \) \
    -print 2>/dev/null \
    | while read -r f
do
    echo "Found: $f"
done

if [ "$SYSTEMD_IOC" -eq 0 ]; then
    pass "no known malicious systemd unit names found"
fi


section "CPAN CACHE / CRON IOCS"

echo "-- cron references --"

CRON_MATCHES="$(
    grep -RnaE \
        '\.cpan/.cache/update|postgresq1|systemct1|open-tls' \
        /etc/cron.d \
        /etc/cron.daily \
        /etc/cron.hourly \
        /etc/cron.weekly \
        /etc/cron.monthly \
        /var/spool/cron \
        2>/dev/null || true
)"

if [ -n "$CRON_MATCHES" ]; then
    critical "known/suspicious cron persistence reference found"
    echo "$CRON_MATCHES"
else
    pass "no known cron IOC references found"
fi

echo
echo "-- suspicious update payload paths --"

CPAN_MATCHES="$(
    find \
        /home \
        /root \
        /usr/local/games \
        -path '*/.cpan/.cache/update' \
        -print 2>/dev/null || true
)"

if [ -n "$CPAN_MATCHES" ]; then
    critical ".cpan/.cache/update payload found"
    echo "$CPAN_MATCHES"

    while read -r f; do
        [ -n "$f" ] || continue
        ls -la "$f" 2>/dev/null || true
        sha256sum "$f" 2>/dev/null || true
    done <<< "$CPAN_MATCHES"
else
    pass "no .cpan/.cache/update payload found"
fi


section "PACKAGEKIT / CVE-2026-41651"

if dpkg-query -W packagekit >/dev/null 2>&1; then
    PKGVER="$(dpkg-query -W -f='${Version}' packagekit 2>/dev/null)"

    info "PackageKit installed: $PKGVER"

    echo
    echo "Package repository information:"
    apt-cache policy packagekit 2>/dev/null || true

    echo
    echo "NOTE:"
    echo "PackageKit being installed is NOT an IOC by itself."
    echo "Distribution packages may contain backported fixes."
else
    pass "PackageKit not installed"
fi

echo
echo "-- PackageKit exploit-style artifacts --"

PK_ARTIFACTS="$(
    find /tmp /var/tmp /dev/shm \
        \( \
            -name 'pkbuild*' \
            -o -name 'pk-dummy*' \
            -o -name 'pk-payload*' \
            -o -path '*/DEBIAN/postinst' \
            -o -path '*/DEBIAN/preinst' \
        \) \
        -print 2>/dev/null || true
)"

if [ -n "$PK_ARTIFACTS" ]; then
    warning "PackageKit exploit-style artifacts found"
    echo "$PK_ARTIFACTS"
else
    pass "no PackageKit exploit-style artifacts found"
fi

echo
echo "-- PackageKit journal indicators --"

PK_JOURNAL="$(
    journalctl --no-pager 2>/dev/null \
        | grep -Ei 'pkbuild|pk-dummy|pk-payload' \
        | grep -vE 'audit: EXECVE.*(pkbuild|pk-dummy|pk-payload)' \
        | tail -100 || true
)"

if [ -n "$PK_JOURNAL" ]; then
    warning "journal contains PackageKit exploit-style artifact names"
    echo "$PK_JOURNAL"
else
    pass "no exploit-style PackageKit journal indicators found"
fi


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

    if [ "${COUNT:-0}" -eq 0 ]; then
        pass "no enabled ftrace functions"
    else
        echo
        echo "-- first 50 hooks --"
        head -50 "$TRACEFILE"

        MODULE_OWNED_COUNT="$(
            grep -Ec '\[[^]]+\]' "$TRACEFILE" 2>/dev/null || true
        )"

        ANON_COUNT="$(
            grep -Ev '\[[^]]+\]|^[[:space:]]*$' "$TRACEFILE" \
                2>/dev/null \
                | wc -l
        )"

        echo
        echo "Hooks with visible module ownership: $MODULE_OWNED_COUNT"
        echo "Hooks without obvious module ownership: $ANON_COUNT"

        if [ "$ANON_COUNT" -gt 20 ]; then
            warning "$ANON_COUNT ftrace hook lines have no obvious module owner"
        elif [ "$MODULE_OWNED_COUNT" -gt 0 ]; then
            info "$COUNT ftrace hooks active; module ownership is visible for at least some hooks"
        else
            info "$COUNT ftrace hooks active"
        fi

        echo
        echo "-- security-sensitive hooked functions --"

        SENSITIVE="$(
            grep -Ei \
              'find_module|__module_address|kallsyms|kill|signal|getdents|readdir|syslog|audit|bpf|init_module|finit_module|openat|stat|tcp_v4_connect|tcp_v6_connect' \
              "$TRACEFILE" 2>/dev/null || true
        )"

        if [ -n "$SENSITIVE" ]; then
            echo "$SENSITIVE"

            SENSITIVE_COUNT="$(printf '%s\n' "$SENSITIVE" | wc -l)"

            if [ "$SENSITIVE_COUNT" -gt 20 ] && [ "$ANON_COUNT" -gt 20 ]; then
                warning "large unexplained security-sensitive ftrace hook set"
            else
                info "$SENSITIVE_COUNT security-sensitive ftrace hook entries found"
            fi
        else
            pass "no selected security-sensitive ftrace hooks detected"
        fi
    fi
else
    info "ftrace enabled_functions unavailable"
fi


section "KERNEL MODULE / TAINT"

TAINT="$(cat /proc/sys/kernel/tainted 2>/dev/null || echo unknown)"

echo "Kernel taint: $TAINT"

if [ "$TAINT" = "0" ]; then
    pass "kernel is not tainted"
elif [ "$TAINT" = "unknown" ]; then
    info "kernel taint status unavailable"
else
    info "kernel is tainted: $TAINT"
    echo "A non-zero taint value is not automatically malicious."
    echo "Third-party drivers/security products commonly taint the kernel."
fi

echo
echo "-- loaded modules --"
lsmod 2>/dev/null | head -100 || true


section "NETWORK IOCS"

echo "-- active TCP connections matching known IOC IPs or :6667 --"

NETIOC="$(
    ss -ntp 2>/dev/null \
        | grep -E ":6667|$IOC_IP_REGEX" || true
)"

if [ -n "$NETIOC" ]; then
    critical "active TCP connection matches known IOC"
    echo "$NETIOC"
else
    pass "no active known TCP IOC connections"
fi

echo
echo "-- active UDP connections matching known IOC IPs --"

UDP_IOC="$(
    ss -nup 2>/dev/null \
        | grep -E "$IOC_IP_REGEX" || true
)"

if [ -n "$UDP_IOC" ]; then
    critical "active UDP connection matches known IOC"
    echo "$UDP_IOC"
else
    pass "no active known UDP IOC connections"
fi


section "RECENT JOURNAL IOC SEARCH"

RECENT_IOC="$(
    journalctl --since "-30 days" --no-pager 2>/dev/null \
        | grep -Ei \
          'postgresq1|systemct1|open-tls|pk-payload|pk-dummy|pkbuild|\.cpan/.cache/update' \
        | grep -vE 'audit: EXECVE.*(postgresq1|systemct1|open-tls|pk-payload|pk-dummy|pkbuild|\.cpan/.cache/update)' \
        | tail -200 || true
)"

if [ -n "$RECENT_IOC" ]; then
    warning "recent journal contains IOC-related strings"
    echo "$RECENT_IOC"
else
    pass "no known IOC strings found in recent journal"
fi


section "FINAL RESULT"

echo "Critical findings : $CRITICAL"
echo "Warnings          : $WARNING"
echo "Informational     : $INFO"
echo

if [ "$CRITICAL" -gt 0 ]; then

    echo -e "${RED}============================================${RESET}"
    echo -e "${RED}  RESULT: POSSIBLE / LIKELY COMPROMISE${RESET}"
    echo -e "${RED}============================================${RESET}"

    echo
    echo "One or more strong indicators matched."
    echo "Preserve evidence before modifying suspicious files."

    exit 2

elif [ "$WARNING" -gt 0 ]; then

    echo -e "${YELLOW}============================================${RESET}"
    echo -e "${YELLOW}  RESULT: REVIEW REQUIRED${RESET}"
    echo -e "${YELLOW}============================================${RESET}"

    echo
    echo "No strong IOC matched, but one or more suspicious findings"
    echo "require manual review."

    exit 1

else

    echo -e "${GREEN}============================================${RESET}"
    echo -e "${GREEN}  RESULT: NO KNOWN IOCS DETECTED${RESET}"
    echo -e "${GREEN}============================================${RESET}"

    echo
    echo "This is a quick IOC check only."
    echo "Absence of these indicators does not prove the host is clean."

    exit 0
fi