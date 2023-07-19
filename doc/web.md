1. [x] Node Uptime
   - [x] Uptime -- время записывается в поле __uptime_begin__ при создании ноды.
   - [x] Peers in/out -- записывается в поле __peers__ при подключении/отключении к нодам из p2p_node
2. [x] Shares -- Один json из MetricGetter = __shares__;
   - [x] Total/Orphaned/Dead -- поле __total__, __orphan__, __dead__ 
   - [x] Efficiency -- поле __efficiency__
3. [x] Pool Rate -- Поле __pool__
   - [x] Hashrate -- Поле __pool.rate__; 
   - [x] % doa + orphaned -- Поле __pool.stale_prop__
   - [x] difficulty -- Поле __pool.difficulty__; В p2pool = min_difficulty
   - [x] network_block_difficulty -- Поле __pool.block_difficulty__
   - [x] network_hashrate -- __pool.network_hashrate__
4. [x] Local Stats ~~Rate~~ -- Поле __local__ 
   - [x] Hashrate -- Поле __local.rate__; состоит из miner_hash_rates и miner_dead_hash_rates.  
   - [x] % doa -- __local.doa__ = __local.miner_dead_hash_rates__/__local.miner_hash_rates__
   - [x] Excepted to share -- Поле __local.time_to_share__
   - [x] block_value -- __local.block_value__ 
5. [ ] Payout
   - [ ] Payout amount -- 
   - [ ] Payout addr -- payout_addr
   - [ ] Expected payout amount -- (local/global_stats.pool_hash_rate*local_stats.block_value*(1-local_stats.donation_proportion))
   - [x] Block value -- __local.block_value__
   - [x] Time to block = local_stats.attempts_to_block/global_stats.pool_hash_rate;
6. [x] Current Payouts -- __current_payouts__;
7. [x] Payout Addr -- __payout_addr__;


__________
# HTML

1. [x] Pool rate
   - [x] pool_rate
   - [x] pool_stale
   - [x] difficulty
2. [x] Node Uptime
   - [x] uptime
   - [x] peers_out
   - [x] peers_in
3. [x] Local rate
   - [x] local_rate
   - [x] local_doa
   - [x] time_to_share
4. [x] Shares
   - [x] shares_total
   - [x] shares_orphan
   - [x] shares_dead
   - [x] efficiency
5. [ ] Payout
   - [ ] payout_amount
   - [ ] symbol
   - [ ] payout_addr
   - [ ] expected_payout_amount
6. Current block
   - [ ] block_value
   - [ ] time_to_block