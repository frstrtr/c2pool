import OkayTracker, data
import argparse
import net as _net
import random
import height_tracker

parser = argparse.ArgumentParser()
parser.add_argument('-shares', action='store', dest='shares')
args = parser.parse_args()

share_store_path = args.shares

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



previous_block = None
bits = None
known_txs_var = {}
get_height_rel_highest = height_tracker.get_height_rel_highest_func(lambda: previous_block)#self.bitcoind, self.factory, lambda: self.bitcoind_work.value['previous_block'], self.net)
best, desired, decorated_heads, bad_peer_addresses = tracker.think(get_height_rel_highest, previous_block, bits, known_txs_var)
print(hex(best))
print(tracker.get_height_and_last(best))