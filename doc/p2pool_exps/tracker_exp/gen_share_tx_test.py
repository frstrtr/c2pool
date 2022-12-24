import OkayTracker, data
import argparse
import net as _net
import random
import height_tracker
import coind_data
import pack
import share

parser = argparse.ArgumentParser()
parser.add_argument('-shares', action='store', dest='shares')
args = parser.parse_args()

share_store_path = args.shares
net = _net


shares = {}
def share_cb(share):
    share.time_seen = 0 # XXX
    shares[share.hash] = share
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

previous_block = None
bits = None
known_txs_var = {}
get_height_rel_highest = height_tracker.get_height_rel_highest_func(lambda: previous_block)#self.bitcoind, self.factory, lambda: self.bitcoind_work.value['previous_block'], self.net)
best, desired, decorated_heads, bad_peer_addresses = tracker.think(get_height_rel_highest, previous_block, bits, known_txs_var)
print('best = {0}'.format(hex(best)))

print('\n=====================\nGenerateShareTransaction\n=====================\n')
share_info, gentx, other_transaction_hashes, get_share = share.NewShare.generate_transaction(
                tracker=tracker,
                share_data=dict(
                    previous_share_hash=best,
                    coinbase=(script.create_push_script([
                        self.current_work.value['height'],
                         ] + ([mm_data] if mm_data else []) + [
                    ]) + self.current_work.value['coinbaseflags'])[:100],
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
                net=net,
                known_txs=tx_map,
                base_subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.current_work.value['height']),
            )