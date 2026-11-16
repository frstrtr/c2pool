#!/usr/bin/env bash
#
# runner-watchdog-mac-intel.sh -- RETIRED 2026-11-13.
#
# This watchdog used to re-register the self-hosted macOS Intel CI runner
# (labels self-hosted,macOS,X64,c2pool-mac-intel). That machine is retired as a
# build host: all macOS builds, including the x86_64 slice of the universal
# package, now run on the Apple Silicon build host (see docs/ci-macos.md), and
# no workflow targets the c2pool-mac-intel labels.
#
# Re-registering a runner on a machine that is no longer a build host would be
# wrong, so the script now does nothing. It is kept as a no-op (exit 0) so a
# leftover cron/launchd entry that still calls it stays harmless; remove that
# entry on the host that runs it. The Apple Silicon watchdog is
# runner-watchdog-mac-arm.sh.
echo "runner-watchdog-mac-intel.sh: retired (the Intel build runner is no longer used); nothing to do" >&2
exit 0
