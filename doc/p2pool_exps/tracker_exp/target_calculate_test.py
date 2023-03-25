import data
import net as _net
import coind_data
import pack
import share
import p2pool_math

net = _net

#############################################333
height = 0

desired_share_target = None
desired_pseudoshare_target = None

if desired_share_target is None:
    desired_share_target = coind_data.difficulty_to_target(float(1.0 / net.PARENT.DUMB_SCRYPT_DIFF))
    local_hash_rate = 0
    if local_hash_rate > 0.0:
        desired_share_target = min(desired_share_target,
            coind_data.average_attempts_to_target(local_hash_rate * net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
    
    lookbehind = 3600//net.SHARE_PERIOD
    block_subsidy = 40170795446
    previous_share = None

    if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
        expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
            * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
        if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
            desired_share_target = min(desired_share_target,
                bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
            )

if height < net.TARGET_LOOKBEHIND:
    pre_target3 = net.MAX_TARGET
else:
    attempts_per_second = get_pool_attempts_per_second(tracker, share_data['previous_share_hash'], net.TARGET_LOOKBEHIND, min_work=True, integer=True)
    pre_target = 2**256//(net.SHARE_PERIOD*attempts_per_second) - 1 if attempts_per_second else 2**256-1
    pre_target2 = math.clip(pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
    pre_target3 = math.clip(pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
max_bits = pack.FloatingInteger.from_target_upper_bound(pre_target3)
bits = pack.FloatingInteger.from_target_upper_bound(p2pool_math.clip(desired_share_target, (pre_target3//30, pre_target3)))

share_info = dict(
    bits = bits
)
print('SHARE_INFO: {0}'.format(share_info['bits']))

if desired_pseudoshare_target is None:
    target = coind_data.difficulty_to_target(float(1.0 / net.PARENT.DUMB_SCRYPT_DIFF))
    local_hash_rate = None
    if local_hash_rate is not None:
        target = coind_data.average_attempts_to_target(local_hash_rate * 1) # target 10 share responses every second by modulating pseudoshare difficulty
    else:
        # If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
        # Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
        # 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
        # one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
        # every ~0.01 seconds.
        target = min(target, 3000 * coind_data.average_attempts_to_target((coind_data.target_to_average_attempts(
            pack.FloatingInteger(int('1b00eacb', 16)).target)*net.SPREAD)*net.PARENT.DUST_THRESHOLD/block_subsidy))
else:
    target = desired_pseudoshare_target
target = max(target, share_info['bits'].target)
target = p2pool_math.clip(target, net.PARENT.SANE_TARGET_RANGE)


pow_hash = int('0000021af02bba79f0619927450b9a2e942be752b7cfce29e00178b7db7904c7', 16)
print('target = {0}'.format(hex(target)))
if pow_hash > target:
    print('Submited')
else:
    print('Pseudoshare')