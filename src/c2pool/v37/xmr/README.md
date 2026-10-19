# c2pool-v37-xmr — the Monero / RandomX pool node (Path B)

> **EXPERIMENTAL.** Regtest, stagenet and testnet run a pool; mainnet runs
> only `--follow-only` (`--i-understand-mainnet` is required even for that).

This directory is the daemon around the Path B lane code: the lane rules,
receipts, carriers, window and coinbase split in `src/impl/xmr/pathb/`, and
the node, relay and stratum glue in `pathb/` here. How to run a node:
[docs/xmr-lane/RUN-A-NODE.md](../../../../docs/xmr-lane/RUN-A-NODE.md).

## Files

| file | role |
|------|------|
| `pathb/pathb_node.hpp` | `PathbNode`: admission, placement, the switch by the journal and its re-pend, templates and jobs |
| `pathb/pathb_relay_node.hpp` | `PathbRelayNode`: the Path B relay (HELLO, frames, the verify pool, catch-up, the re-offer, the joiner, context blocks) |
| `pathb/pathb_relay_links.hpp` | `CarrierLinks`: the relay's TCP links over `carrier_net.hpp` |
| `pathb/pathb_job_source.hpp`, `pathb/pathb_stratum*.hpp`, `pathb/pathb_own_share.hpp` | the stratum template source, the stratum hooks, the node's own shares |
| `pathb/pathb_template_select.hpp` | the template's transaction selection |
| `pathb/pathb_follow_only.hpp`, `pathb/pathb_follow_template.hpp` | `--follow-only` |
| `pathb/pathb_mainnet_refusal.hpp`, `pathb/pathb_startup.hpp` | the start-up checks and refusals |
| `pathb/pathb_status.hpp`, `xmr_web_dashboard.*` | the status lines and the web status |
| `pathb/xmr_pathb_store.*`, `pathb/pathb_follower_rows.hpp` | the Path B store, the follower's rows |
| `xmr_node_config.hpp` | the configuration surface and the flag parser |
| `xmr_node.hpp` | the descriptor backends (installed and checked at start) |
| `xmr_native_chain_source.hpp`, `xmr_native_template_backend.hpp` | the embedded native Monero node as the chain and template source |
| `xmr_live_transport.hpp`, `xmr_live_submit.hpp` | the monerod RPC transport and found-block submit |
| `xmr_p2p_block_publisher.hpp` | found-block publish over levin |
| `xmr_o2_randomx_verify.hpp` | RandomX verify |
| `xmr_stratum_listener.hpp`, `xmr_lane_suspend_state.hpp`, `xmr_lane_resume_fresh.hpp` | the stratum listener and its suspend / resume gate |
| `xmr_lane_constants.hpp` | lane constants shared by the configuration and stratum |
| `relay/` | the relay's address book and peer store, the bootstrap list, the chain-view feed, the context-block module, payout addresses (`xmr_address.hpp`) and the kept frames (`xmr_relay_wire.hpp`) |
| `../main_v37_xmr.cpp` | the `c2pool-v37-xmr` entrypoint |
