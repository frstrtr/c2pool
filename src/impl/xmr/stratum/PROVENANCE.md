# Provenance — XMR stratum front-end (Family B)

Every PATTERN below is re-expressed as fresh AGPL-3.0 c2pool code; **no p2pool
source lines are copied verbatim** into the `.hpp`/`.cpp`. p2pool is GPL-3.0 and
combines lawfully into c2pool (AGPL-3.0) under AGPLv3 §13; had any file been
copied verbatim it would carry p2pool's GPL-3.0 header plus a provenance line —
none was, because the stratum layer here is a clean re-implementation of the
wire dialect, deliberately shed of p2pool's transport and pool-model coupling.

## Upstream
- **Repo:** `SChernykh/p2pool` @ `master` (read 2026-09-05)
- **License:** GPL-3.0
- **Files read:** `src/stratum_server.h`, `src/stratum_server.cpp`
- **Design-of-record cross-check:** `v37-monero-randomx-lane-scoping.md` §2.5, §3.4, §4, §5

## PATTERN map (p2pool symbol → this leg)

| p2pool symbol / lines | What it does | Re-expressed as |
|---|---|---|
| `StratumClient::process_request` L1452-1514 | JSON parse + method dispatch (`login`/`submit`/`keepalived`) | dispatch is the host transport's; dialect exposes `parse_submit` / `parse_login_string` + `handle_login`/`handle_submit` |
| `on_login` response L340-346 | login OK JSON with nested `job` object | `StratumDialect::build_login_ok` (byte-for-byte, + `next_seed_hash`) |
| `on_blobs_ready` job push L941-946 | `{"method":"job","params":{…}}` | `StratumDialect::build_job_notify` |
| `on_login` target trunc L332-337 / `on_blobs_ready` L933-938 | 4-byte compact vs 8-byte target, LE | `StratumDialect::encode_target` (+ `TARGET_4_BYTES_LIMIT`) |
| `process_submit` L1547-1619 | validate + extract `id`/`job_id`/`nonce`/`result`; length checks (8 / 64 hex) | `SubmitFields` (transport-filled) + `StratumDialect::parse_submit` |
| `on_submit` decode L361-395 | job_id hex→u32 (nonzero), nonce 8-hex **little-endian**→u32, result 64-hex→32 B | `StratumDialect::parse_submit` (same accumulation order) |
| `on_submit` fast block check L428-431 | if hash clears mainchain diff → `submit_block_async` | `handle_submit` stage (1) → `IShareSink::submit_network_block` |
| `on_share_found` recompute L1068-1095 | rebuild blob from `(template_id, extra_nonce)`, write nonce at `nonce_offset`, **recompute** RandomX hash, force-light re-hash for unstable-HW | `handle_submit` stage (2): `ITemplateSource::rebuild_blob` + nonce insert + `IPowVerifier::randomx_hash` (force-light hook noted) |
| result/error JSON L1220-1241 | `"Stale share"`, `"Low diff share"`, `"Invalid PoW"`, `{"status":"OK"}`, … | `SubmitError` + `submit_error_message` + `build_status_ok`/`build_error` |
| `StratumClient::SavedJob` + `m_jobs[JOBS_SIZE=4]` L72-77 | 4-deep per-connection job ring | `XmrStratumSession::SavedJob` + `m_jobs[JOBS_RING=4]` |
| `m_extraNonce` atomic + `fetch_add` L166, L280 | per-server unique extra_nonce allocator | `XmrStratumServer::m_extraNonce` / `get_next_extra_nonce` |
| `BlockTemplate::get_hashing_blob(extra_nonce,…)` L291 | bake extra_nonce into `miner_tx.extra` (tag `0x02`), return per-client blob + seed + nonce_offset + template_id | `ITemplateSource::get_job` / `rebuild_blob` + `TemplateJob` |
| `p2pool::calculate_hash` / `RandomX_Hasher::calculate` (pow_hash.cpp) | RandomX light/dataset hash, two-cache epoch straddle | `IPowVerifier::randomx_hash` (+ `meets_target`) |
| `get_custom_diff` / `get_custom_user` (util.cpp) | parse `+diff` / worker out of the login string | `StratumDialect::parse_login_string` → `LoginString` |
| `send_http_response` L1622 | GET → "P2Pool Stratum online" | out of scope (transport concern; noted) |

## DELIBERATELY NOT PORTED (p2pool pool-model — v37 has its own RDWR model)
- Sidechain / `PoolBlock` / `m_sidechainId` — a v37 accepted share is a
  work-receipt candidate handed to `IShareSink::on_accepted_share`, not a
  sidechain block.
- **PPLNS window** (`get_shares`, `m_chainWindowSize`, `MAX_PPLNS_WINDOW_HOURS`)
  and the dynamic 2× weight cap.
- **Uncles** (`UNCLE_BLOCK_DEPTH`, `MAX_UNCLES_PER_BLOCK`, `m_unclePenalty`).
- libuv / `TCPServer` / `uv_work_t` share-check queue / bans / hashrate ring —
  all transport/host concerns behind `ITransport` (bans + auto-diff kept as
  hooks only).

## DIVERGENCES (added on purpose)
1. **`next_seed_hash` in the job** — p2pool omits it; the xmrig protocol and
   monerod `get_block_template` both carry it, and RandomX clients use it to
   pre-init the cache/dataset for the coming 2048-block epoch so seed rotation
   is hitless (scoping §1.1, §4). Optional field on `JobNotify`.
2. **Recompute-only PoW trust** — the client-reported `result` is never trusted
   for validity; `handle_submit` always recomputes via `IPowVerifier`. (p2pool
   also recomputes; here it is the single authoritative path.)
