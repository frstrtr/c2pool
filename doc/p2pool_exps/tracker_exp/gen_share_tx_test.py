import OkayTracker, data
import argparse
import net as _net
import random
import height_tracker
import coind_data
import pack
import share as SHARE
import p2pool_math
import time
import script

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
current_work = {'height':0, 'coinbaseflags':'', 'subsidy':0, 'transaction_fees':[], 'bits':0}
donation_percentage = 0.0
pubkey_hash = int('78ecd67a8695aa4adc55b70f87c2fa3279cee6d0', 16)
desired_share_target = int('00000000359dc900000000000000000000000000000000000000000000000000', 16)
get_stale_counts = lambda : ((0,0), 0, (0,0))
share_type = SHARE.Share

share_info, gentx, other_transaction_hashes, get_share = share_type.generate_transaction2(
                tracker=tracker,
                share_data=dict(
                    previous_share_hash=best,
                    coinbase=(script.create_push_script([current_work['height']] + []) 
                        + current_work['coinbaseflags'])[:100],
                    nonce=random.randrange(2**32),
                    pubkey_hash=pubkey_hash,
                    subsidy=current_work['subsidy'],
                    donation=p2pool_math.perfect_round(65535*donation_percentage/100),
                    stale_info=(lambda (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain):
                        'orphan' if orphans > orphans_recorded_in_chain else
                        'doa' if doas > doas_recorded_in_chain else
                        None
                    )(*get_stale_counts()),
                    desired_version=17#(share.Share.SUCCESSOR if share.Share.SUCCESSOR is not None else share.Share).VOTING_VERSION,
                ),
                block_target=pack.FloatingInteger(current_work['bits']).target,
                desired_timestamp=int(time.time() + 0.5),
                desired_target=desired_share_target,
                ref_merkle_link=dict(branch=[], index=0),
                desired_other_transaction_hashes_and_fees=[],
                net=net,
                known_txs=[],
                base_subsidy=7200000000000#net.PARENT.SUBSIDY_FUNC(current_work['height']),
            )

#share_info, gentx, other_transaction_hashes, get_share
print("RESULT:")
print('\nshare_info = {0}\n'.format(share_info))
print('gentx = {0}'.format(gentx))
print('other_tx_hashes = {0}'.format(other_transaction_hashes))
print('coinbase: [{0}], first part = [{1}], second part = [{2}]'.format((script.create_push_script([current_work['height']] + []) 
                        + current_work['coinbaseflags'])[:100], script.create_push_script([current_work['height']] + []), current_work['coinbaseflags']))


for tx in gentx['tx_outs']:
    print('TX: {0}'.format(tx))
    print('script: {0}\n'.format([ord(x) for x in tx['script']]))

#1
#c2pool: 106, 36, 170, 33, 169, 237, 82, 121, 208, 219, 62, 217, 225, 145, 115, 20, 19, 42, 211, 74, 46, 23, 133, 225, 176, 102, 66, 45, 41, 227, 137, 221, 66, 82, 29, 79, 69, 243
#p2pool: 106, 36, 170, 33, 169, 237, 82, 121, 208, 219, 62, 217, 225, 145, 115, 20, 19, 42, 211, 74, 46, 23, 133, 225, 176, 102, 66, 45, 41, 227, 137, 221, 66, 82, 29, 79, 69, 243

#2
#c2pool: 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174
#p2pool: 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174

#3
#c2pool: 106, 40, 110, 203, 27, 211, 241, 93, 142, 151, 214, 124, 43, 128, 188, 54, 128, 8, 99, 13, 75, 199, 71, 27, 181, 115, 148, 221, 122, 16, 130, 208, 102, 104, 32, 89, 144, 40, 254, 127, 0, 0
#p2pool: 106, 40, 211, 40, 91, 214, 11, 69, 220, 154, 66, 49, 77, 129, 189, 229, 205, 40, 249, 212, 121, 106, 242, 127, 255, 116, 190, 188, 21, 227, 246, 33, 145, 11, 0, 0, 0, 0, 0, 0, 0, 0

#get_ref_hash:
