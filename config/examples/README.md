# Example settings files (TOML)

Commented example settings files for the c2pool node binaries, checked against
the v0.2.12.1 release binaries. Copy one, edit it, and pass it with
`--settings PATH`, or save it as `<data-dir>/c2pool.toml`. The mechanism is
described in the main README under
[Settings file (TOML) — all binaries](../../README.md#settings-file-toml--all-binaries).

Each file has two parts. The upper part holds the keys that binary applies from
a file; the non-money keys are set (the file loads with no money ack), the
money keys are commented out. The **REFERENCE** block at the end lists the keys
the loader accepts but the binary does not apply in this release: setting them
in the file has no effect (they still print as `source=file` in the dump), so
use the CLI flag named next to each.

- **[c2pool-ltc.toml](c2pool-ltc.toml)** — Litecoin with merged-mined Dogecoin.
  Daemonless by default (embedded LTC and DOGE SPV are compiled on). The file
  sets the web port and bind address and the Stratum port; fees, donation and
  payout addresses are commented-out money keys. DOGE payout addresses
  (`--merged-payout-address`, `--node-owner-merged-address`) are command-line
  only. Do not combine it with the legacy `--config` YAML: the YAML wins.
- **[c2pool-dash.toml](c2pool-dash.toml)** — Dash. Daemonless as long as
  neither `daemon_rpc` key is set. The web port is moved from its default 8080
  to 8082 so it does not collide with c2pool-ltc on the same host; Stratum is
  turned on at 7903. Start with `--run` on the command line.
- **[c2pool-btc.toml](c2pool-btc.toml)** — Bitcoin. `coin_p2p.discover = true`
  makes it daemonless, and with this file the binary needs no other flag to
  start. Stratum 9334, web 8083.
- **[c2pool-bch.toml](c2pool-bch.toml)** — Bitcoin Cash. Daemonless via
  `coin_p2p.discover = true`; web 8085. `--pool` and `--stratum` are
  command-line only in this release.
- **[c2pool-dgb.toml](c2pool-dgb.toml)** — DigiByte (mainnet only).
  Daemonless via `coin_p2p.discover = true`; web 8084. `--run` and `--stratum`
  are command-line only in this release.

The ports in these files do not collide, so all five nodes can run on one host.

## The three commands

```bash
# 1. Check: print every resolved key with its source, exit 0, start nothing
./c2pool-ltc --settings c2pool-ltc.toml --dump-resolved-config

# 2. Only after uncommenting a [money] key: print the money-ack hash (last
#    line of the output), then put it in [gate] money_ack_hash in the file
./c2pool-ltc --settings c2pool-ltc.toml --ack-money-settings

# 3. Run
./c2pool-ltc --settings c2pool-ltc.toml
```

Replace `ltc` with the coin you run, and add `--run` (dash, dgb) or `--pool`
(bch) to step 3. A file with a money key and no matching hash is refused with
exit 78; any change to a money key needs a new hash.

Command-line flags always override the file (compiled defaults < file < CLI),
so a flag such as `--web-port 9000` wins over `[ltc.web] port`. For the same
reason, do not start these nodes through `start.sh` when you use a settings
file: it adds its own `--stratum`, `--http` and similar flags.
