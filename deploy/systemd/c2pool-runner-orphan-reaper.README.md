# c2pool CI runner-host orphan-build reaper

Unattended guard for self-hosted **Linux** CI runner hosts. Reaps build trees
(`cmake`/`make`/`cc1plus`/`cc`/`c++`) that a dead `Runner.Worker` left
reparented to `ppid=1`, where they peg host load and starve the runner pool
(observed on 192.168.86.198, 2026-08-02).

Companion of the mac self-heal watchdogs in `scripts/ci/runner-watchdog-mac-*.sh`.
Script: `scripts/ci/runner-orphan-reaper-linux.sh` (self-documenting header).

## Why ppid=1 is the signal
A legit compiler always has a live `Runner.Worker` ancestor. When the Worker
dies, the kernel reparents its orphans to pid 1 — so `ppid=1` + build-comm +
under `_work/.../build` (incl. build_codeql) = orphaned, by construction. This is safe on
**multi-runner hosts** (VM905 = 8 runners): a busy sibling runner's compilers
are children of *its* live Worker, never `ppid=1`, so they are never touched.
An age floor (>15 min) is layered on as belt-and-suspenders. The script also
does an explicit Worker-ancestor walk right before any signal (HARD rule:
never touch a tree under a live Runner.Worker).

## Install (per Linux runner host — .198 primary; then VM905 / 198-2 / 198-3)

    mkdir -p ~/.local/bin ~/.config/systemd/user ~/.local/state/runner-orphan-reaper
    cp scripts/ci/runner-orphan-reaper-linux.sh ~/.local/bin/
    chmod +x ~/.local/bin/runner-orphan-reaper-linux.sh
    cp deploy/systemd/c2pool-runner-orphan-reaper.service \
       deploy/systemd/c2pool-runner-orphan-reaper.timer   ~/.config/systemd/user/
    loginctl enable-linger "$USER"            # keep the timer firing without a login session
    systemctl --user daemon-reload
    systemctl --user enable --now c2pool-runner-orphan-reaper.timer

## Verify / safe rehearsal (kills nothing)

    systemctl --user list-timers c2pool-runner-orphan-reaper.timer
    ~/.local/bin/runner-orphan-reaper-linux.sh --dry-run     # prints what WOULD be reaped
    journalctl --user -t runner-orphan-reaper -n 50
    journalctl --user -u c2pool-runner-orphan-reaper.service -n 50

## Tunables (env; defaults match the .198 incident)
- `REAP_PATH_RE`    build-tree path regex. Default `_work/.*/build` (covers
                    both build_codeql and the coin-matrix build dir). Narrow to
                    `_work/.*build_codeql` for CodeQL-only hosts.
- `REAP_COMM_RE`    toolchain leader `comm` set.
- `REAP_MIN_AGE`    age floor, seconds (default 900).
- `REAP_ROOT_PPID`  orphan-root parent pid (default 1; change only if the host
                    installs a child-subreaper in the runner tree).
- `REAP_ALERT_MAILTO`  if set and a local `mail`/`sendmail` exists, each kill is
                    ALSO emailed inline. Otherwise kills are journalled and
                    appended to `REAP_SPOOL` (`~/.local/state/runner-orphan-reaper/
                    reaped.jsonl`), which ci-steward tails each heartbeat to
                    forward to decisions@ for recurrence tracking.

## Revert
    systemctl --user disable --now c2pool-runner-orphan-reaper.timer
    rm ~/.config/systemd/user/c2pool-runner-orphan-reaper.{service,timer} ~/.local/bin/runner-orphan-reaper-linux.sh
No persistent host change is made beyond killing the orphaned processes it reports.
