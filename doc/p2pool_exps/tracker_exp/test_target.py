import coind_data
import pack
import p2pool_math

# data
POW_HASH = int('0000011c91e9696fd65bffa9c70d8ede638f2419cc94c4f02e4a1ec45ecc36a0', 16)

MAX_TARGET = 2 ** 256 // 2 ** 20 - 1
DUMB_SCRYPT_DIFF = 2**16
SANE_TARGET_RANGE = (2**256//2**33 - 1, 2**256//2**31 - 1)
DUST_THRESHOLD = 0.03e8
desired_pseudoshare_target = None
SPREAD=30

# desired_target
desired_share_target = coind_data.difficulty_to_target(float(1.0 / DUMB_SCRYPT_DIFF))
print("des = {0}".format(hex(desired_share_target)))

# local_hash_rate = local_addr_rates.get(pubkey_hash, 0)
# if local_hash_rate > 0.0:
#     desired_share_target = min(desired_share_target,
#                                 bitcoin_data.average_attempts_to_target(local_hash_rate * self.node.net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty

# lookbehind = 3600//self.node.net.SHARE_PERIOD
# block_subsidy = self.node.bitcoind_work.value['subsidy']
# if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
#     expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
#                                 * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
#     if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
#         desired_share_target = min(desired_share_target,
#                                     bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
#                                     )
desired_target = desired_share_target
coind_work = dict(bits=pack.FloatingInteger(int("207fffff", 16)))
# coind_work = dict(bits=pack.FloatingInteger(545259519))
block_subsidy = 788059900000


# normal
def normal_test():
    pre_target3 = MAX_TARGET
    max_bits = pack.FloatingInteger.from_target_upper_bound(pre_target3)
    bits = pack.FloatingInteger.from_target_upper_bound(
        p2pool_math.clip(desired_target, (pre_target3 // 30, pre_target3)))

    print('DESIRED TARGET: {0}'.format(hex(desired_target)))
    print('pre_target3 // 30: {0}'.format(hex(pre_target3 // 30)))
    print('pre_target3: {0}'.format(hex(pre_target3)))
    print('p2pool_math.clip(desired_target, (pre_target3 // 30, pre_target3)): {0}'.format(hex(p2pool_math.clip(desired_target, (pre_target3 // 30, pre_target3)))))
    print('bits: {0}'.format(bits))

    if desired_pseudoshare_target is None:
        target = coind_data.difficulty_to_target(float(1.0 / DUMB_SCRYPT_DIFF))
        # local_hash_rate = self._estimate_local_hash_rate()
        local_hash_rate = None
        if local_hash_rate is not None:
            target = coind_data.average_attempts_to_target(
                local_hash_rate * 1)  # target 10 share responses every second by modulating pseudoshare difficulty
        else:
            # If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
            # Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
            # 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
            # one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
            # every ~0.01 seconds.
            target = min(target,
                         3000 * coind_data.average_attempts_to_target((coind_data.target_to_average_attempts(
                             coind_work['bits'].target) * SPREAD) * DUST_THRESHOLD / block_subsidy))
    else:
        target = desired_pseudoshare_target
    target = max(target, bits.target) #share_info['bits'].target
    # for aux_work, index, hashes in mm_later:
    #     target = max(target, aux_work['target'])
    target = p2pool_math.clip(target, SANE_TARGET_RANGE)

    print("BLOCKHEADER.TARGET: {0}".format(hex(coind_work['bits'].target)))
    print("SHARE_INFO.TARGET: {0}".format(hex(bits.target)))
    print("TARGET: {0}".format(hex(target)))

    print('pow_hash <= header.target: {0}'.format(POW_HASH <= coind_work['bits'].target))
    print('pow_hash <= share_info.target: {0}'.format(POW_HASH <= coind_work['bits'].target))
    print('pow_hash > target: {0}'.format(POW_HASH > target))

    return hex(coind_work['bits'].target), hex(bits.target), hex(target)

print('NORMAL: ')
test1 = normal_test()


# not normal
def not_normal_test():
    DUMB_SCRYPT_DIFF = 256

    pre_target3 = MAX_TARGET
    max_bits = pack.FloatingInteger.from_target_upper_bound(pre_target3)
    bits = pack.FloatingInteger.from_target_upper_bound(
        p2pool_math.clip(desired_target, (pre_target3 // 30, pre_target3)))

    if desired_pseudoshare_target is None:
        target = coind_data.difficulty_to_target(float(1.0 / DUMB_SCRYPT_DIFF))
        # local_hash_rate = self._estimate_local_hash_rate()
        local_hash_rate = None
        if local_hash_rate is not None:
            target = coind_data.average_attempts_to_target(
                local_hash_rate * 1)  # target 10 share responses every second by modulating pseudoshare difficulty
        else:
            # If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
            # Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
            # 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
            # one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
            # every ~0.01 seconds.
            target = min(target,
                         3000 * coind_data.average_attempts_to_target((coind_data.target_to_average_attempts(
                             coind_work['bits'].target) * SPREAD) * DUST_THRESHOLD / block_subsidy))
    else:
        target = desired_pseudoshare_target
    target = max(target, bits.target) #share_info['bits'].target
    # for aux_work, index, hashes in mm_later:
    #     target = max(target, aux_work['target'])
    target = p2pool_math.clip(target, SANE_TARGET_RANGE)

    print("BLOCKHEADER.TARGET: {0}".format(hex(coind_work['bits'].target)))
    print("SHARE_INFO.TARGET: {0}".format(hex(bits.target)))
    print("TARGET: {0}".format(hex(target)))

    print('pow_hash <= header.target: {0}'.format(POW_HASH <= coind_work['bits'].target))
    print('pow_hash <= share_info.target: {0}'.format(POW_HASH <= coind_work['bits'].target))
    print('pow_hash > target: {0}'.format(POW_HASH > target))
    return hex(coind_work['bits'].target), hex(bits.target), hex(target)

print('NOT NORMAL: ')
test2 = not_normal_test()

print('test1 == test2: {0}'.format(test1==test2))