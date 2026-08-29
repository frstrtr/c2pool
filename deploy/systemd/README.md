# c2pool D-MINER user-systemd deployment

Reproducible units for the per-miner presence + notification pipeline. They run
as **user** services (no root) with lingering enabled, matching how the sampler
is already deployed on the contabo prod node.

Pipeline:
- `c2pool-miner-sampler.service` — D-MINER.1 sampler, long-running; polls this
  node `/local_stats` every `C2POOL_SAMPLE_INTERVAL`s into `miner_presence.db`.
- `c2pool-miner-rollup.{service,timer}` — nightly (00:10) per-worker/day rollup.
- `c2pool-miner-notify.{service,timer}` — D-MINER.5 engine `run`, every 5 min;
  emits offline / back-online / hashrate-drop alerts (throttled, transport-agnostic).
- `c2pool-miner-daily.{service,timer}` — daily-summary (08:00, after the rollup).

Nothing is hardcoded: every path, URL, and transport setting lives in
`~/.config/c2pool/miner.env` so each node stays per-node truthful.

## Install (per node)

    mkdir -p ~/.config/c2pool ~/.config/systemd/user ~/.local/share/c2pool
    cp c2pool-miner.env.example ~/.config/c2pool/miner.env
    $EDITOR ~/.config/c2pool/miner.env        # set scripts dir, DB, /local_stats URL, SMTP
    cp c2pool-miner-*.service c2pool-miner-*.timer ~/.config/systemd/user/
    loginctl enable-linger "$USER"            # survive logout / keep timers firing
    systemctl --user daemon-reload
    systemctl --user enable --now c2pool-miner-sampler.service
    systemctl --user enable --now c2pool-miner-rollup.timer c2pool-miner-notify.timer c2pool-miner-daily.timer

Seed a worker subscription before notify can route:

    python3 \$C2POOL_MINER_SCRIPTS/miner_notify_engine.py subscribe \
      --db \$C2POOL_MINER_DB --worker <addr.worker> --route <email> --channels email

## Verify / dry-run

    systemctl --user list-timers "c2pool-miner-*"
    journalctl --user -u c2pool-miner-notify.service -n 50
    # safe rehearsal (forces logonly transport, no mail sent):
    python3 \$C2POOL_MINER_SCRIPTS/miner_notify_engine.py run --db \$C2POOL_MINER_DB --dry-run
