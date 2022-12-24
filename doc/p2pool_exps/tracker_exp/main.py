import OkayTracker, data
import argparse
import net as _net
import random
import height_tracker
import coind_data
import pack
import share
import script

parser = argparse.ArgumentParser()
parser.add_argument('-shares', action='store', dest='shares')
args = parser.parse_args()

share_store_path = args.shares

# print(pack.FloatingIntegerType().unpack('1b00f7a2'.decode('hex')).target)
# exit()

# Network
net = _net
# print(net.P2P_PORT)
## import coind_data
## print(coind_data.hash256('21fd8501fe02000020e4e3d0eabf481c20fa7c944837949dc3473af239fe72597b29da69ddcb6af3c6aff388637d2a011b050786be9001e5e4be93b49d2dd715ba8e3f7c57bef7d4eef1b029692e646beac3d690543d04f067f7002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5f53ed6880bb351fc9fbbd8e1f40942130e77131978df6de41e6434dc8090000000000002101121677202158c88bb36f93ce9ff836faa31eba8cd0a4d1111fc66664a3a1ac4f68e2a87354c83203f43cf077f91991da32b1bdf15160716da281f4109357ecc90001010046d6cbcfa5c991cb642713fc90740b64826d4a2fa455af02169e6728ab978671ffff0f1e68ca0b1eaff3886385d903006e10caeb2c0400000000000000000000000000000001000000e48269c4099da5b66eb1d62a873c7a9e2e3e1026996c6cfcbf7fcf0165d8d0c7fd9c0101121677202158c88bb36f93ce9ff836faa31eba8cd0a4d1111fc66664a3a1ac4f'))
## print(net.PARENT.POW_FUNC('21fd8501fe02000020e4e3d0eabf481c20fa7c944837949dc3473af239fe72597b29da69ddcb6af3c6aff388637d2a011b050786be9001e5e4be93b49d2dd715ba8e3f7c57bef7d4eef1b029692e646beac3d690543d04f067f7002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5f53ed6880bb351fc9fbbd8e1f40942130e77131978df6de41e6434dc8090000000000002101121677202158c88bb36f93ce9ff836faa31eba8cd0a4d1111fc66664a3a1ac4f68e2a87354c83203f43cf077f91991da32b1bdf15160716da281f4109357ecc90001010046d6cbcfa5c991cb642713fc90740b64826d4a2fa455af02169e6728ab978671ffff0f1e68ca0b1eaff3886385d903006e10caeb2c0400000000000000000000000000000001000000e48269c4099da5b66eb1d62a873c7a9e2e3e1026996c6cfcbf7fcf0165d8d0c7fd9c0101121677202158c88bb36f93ce9ff836faa31eba8cd0a4d1111fc66664a3a1ac4f'))
## exit()
# tracker = tracker.Tracker()

shares = {}
def share_cb(share):
    share.time_seen = 0 # XXX
    shares[share.hash] = share
    # print(hex(share.hash))
    # print(type(share.hash))
    # print(share.hash)
    if len(shares) % 1000 == 0 and shares:
        print("    %i" % (len(shares),))

known_verified = set()

share_store = data.ShareStore(net, share_store_path, share_cb, known_verified.add)

# print(len(shares))
# print(len(known_verified))
assert(int('14a875701d88f6421211b8ffb4ba5248295905edb3bdd47312e2022abdd97374',16) in shares)
# print('0x14a875701d88f6421211b8ffb4ba5248295905edb3bdd47312e2022abdd97374L' in known_verified)

tracker = OkayTracker.OkayTracker(net)

for share in shares.values():
    tracker.add(share)
        
for share_hash in known_verified:
    if share_hash in tracker.items:
        tracker.verified.add(tracker.items[share_hash])

print('{0}-{1}'.format(len(tracker.items), len(tracker.verified.items)))
print('shares: {0}/{1}'.format(len(tracker.heads), len(tracker.tails)))
print('verified: {0}/{1}'.format(len(tracker.verified.heads), len(tracker.verified.tails)))

previous_block = None
bits = None
known_txs_var = {}
get_height_rel_highest = height_tracker.get_height_rel_highest_func(lambda: previous_block)#self.bitcoind, self.factory, lambda: self.bitcoind_work.value['previous_block'], self.net)
best, desired, decorated_heads, bad_peer_addresses = tracker.think(get_height_rel_highest, previous_block, bits, known_txs_var)
print(hex(best))
b_height, b_last = tracker.get_height_and_last(best)
print(tracker.get_height_and_last(best))


print('\n=====================\nGetCumulativeWeights\n=====================\n')
print(hex(coind_data.target_to_average_attempts(0)))
print(hex(best))
print(max(0, min(b_height, net.REAL_CHAIN_LENGTH) - 1))
# print(hex(65535*net.SPREAD*(coind_data.target_to_average_attempts(0)-1)))
print('attempts = {0}'.format(hex(coind_data.target_to_average_attempts(0))))
print(hex(65535*net.SPREAD*coind_data.target_to_average_attempts(0)))

weights, total_weight, donation_weight = tracker.get_cumulative_weights(best, 
    max(0, min(b_height, net.REAL_CHAIN_LENGTH) - 1),
    65535*net.SPREAD*coind_data.target_to_average_attempts(0)
)

print('\nweights = {0}'.format(weights))
print('total_weight = {0}'.format(total_weight))
print('donation_weight = {0}'.format(donation_weight))


print('\n=====================\nGenerateShareTransaction\n=====================\n')
share_info, gentx, other_transaction_hashes, get_share = share.Share.generate_transaction(
                tracker=tracker,
                share_data=dict(
                    previous_share_hash=best,
                    coinbase=(script.create_push_script([self.current_work.value['height']] + []) 
                        + self.current_work.value['coinbaseflags'])[:100],
                    nonce=random.randrange(2**32),
                    pubkey_hash=pubkey_hash,
                    subsidy=self.current_work.value['subsidy'],
                    donation=math.perfect_round(65535*self.donation_percentage/100),
                    stale_info=(lambda (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain):
                        'orphan' if orphans > orphans_recorded_in_chain else
                        'doa' if doas > doas_recorded_in_chain else
                        None
                    )(*self.get_stale_counts()),
                    desired_version=(share_type.SUCCESSOR if share_type.SUCCESSOR is not None else share_type).VOTING_VERSION,
                ),
                block_target=self.current_work.value['bits'].target,
                desired_timestamp=int(time.time() + 0.5),
                desired_target=desired_share_target,
                ref_merkle_link=dict(branch=[], index=0),
                desired_other_transaction_hashes_and_fees=zip(tx_hashes, self.current_work.value['transaction_fees']),
                net=self.node.net,
                known_txs=tx_map,
                base_subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.current_work.value['height']),
            )