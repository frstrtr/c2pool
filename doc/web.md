1. [x] Node Uptime
   - [x] Uptime -- время записывается в поле __uptime_begin__ при создании ноды.
   - [x] Peers in/out -- записывается в поле __peers__ при подключении/отключении к нодам из p2p_node
2. [x] Shares -- Один json из MetricGetter = __shares__;
   - [x] Total/Orphaned/Dead -- поле __total__, __orphan__, __dead__ 
   - [x] Efficiency -- поле __efficiency__
3. [ ] Pool Rate
   - [ ] Hashrate -- Поле __pool_hashrate__; 
   - [ ] % doa + orphaned -- Поле __pool_stale__
   - [ ] difficulty -- Поле __difficulty__; В p2pool = min_difficulty
4. [x] Local Stats ~~Rate~~ -- Поле __local__ 
   - [x] Hashrate -- Поле __local.rate__; состоит из miner_hash_rates и miner_dead_hash_rates.  
   - [x] % doa -- __local.doa__ = __local.miner_dead_hash_rates__/__local.miner_hash_rates__
   - [x] Excepted to share -- Поле __local.time_to_share__
5. [ ] Payout
   - [ ] Payout amount --
   - [ ] Payout addr -- 
   - [ ] Expected payout amount --
   - [ ] Block value
   - [ ] Time to block