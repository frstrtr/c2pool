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
import work
import variable

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

# share_info, gentx, other_transaction_hashes, get_share = share_type.generate_transaction2(
#                 tracker=tracker,
#                 share_data=dict(
#                     previous_share_hash=best,
#                     coinbase=(script.create_push_script([current_work['height']] + []) 
#                         + current_work['coinbaseflags'])[:100],
#                     nonce=random.randrange(2**32),
#                     pubkey_hash=pubkey_hash,
#                     subsidy=current_work['subsidy'],
#                     donation=p2pool_math.perfect_round(65535*donation_percentage/100),
#                     stale_info=(lambda (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain):
#                         'orphan' if orphans > orphans_recorded_in_chain else
#                         'doa' if doas > doas_recorded_in_chain else
#                         None
#                     )(*get_stale_counts()),
#                     desired_version=17#(share.Share.SUCCESSOR if share.Share.SUCCESSOR is not None else share.Share).VOTING_VERSION,
#                 ),
#                 block_target=pack.FloatingInteger(current_work['bits']).target,
#                 desired_timestamp=int(time.time() + 0.5),
#                 desired_target=desired_share_target,
#                 ref_merkle_link=dict(branch=[], index=0),
#                 desired_other_transaction_hashes_and_fees=[],
#                 net=net,
#                 known_txs=[],
#                 base_subsidy=7200000000000#net.PARENT.SUBSIDY_FUNC(current_work['height']),
#             )

# #share_info, gentx, other_transaction_hashes, get_share
# print("RESULT:")
# print('\nshare_info = {0}\n'.format(share_info))
# print('gentx = {0}'.format(gentx))
# print('other_tx_hashes = {0}'.format(other_transaction_hashes))
# print('coinbase: [{0}], first part = [{1}], second part = [{2}]'.format((script.create_push_script([current_work['height']] + []) 
#                         + current_work['coinbaseflags'])[:100], script.create_push_script([current_work['height']] + []), current_work['coinbaseflags']))

def bytes_to_data(bytes):
    res = b''
    for x in bytes:
        res += chr(x)
    return res #str(res).replace(', ', ' ')

print('\n=====================\nWorker::get_work\n=====================\n')

class FakeP2PNode:

    def __init__(self):
        self.peers = [None]

class FakeCoindNode:

    def get_fake_bitcoind_work(self):
        res = dict(
            version=536870914,
            previous_block = int('1e47a6e2224db5bc2ddce3c31eb14dac8b02ca5a05ebd077d9f53a8d092e4226',16),
            bits = pack.FloatingInteger(453045919),
            coinbaseflags = "",
            height = 16518948,
            time = 1674480469,
            transactions = [
                dict(
                    version = 1,
                    tx_ins = [
                        dict(
                            previous_output = dict(
                                hash = int('46683430f87c6ceb23628e0a1908438b3288f256218acef83b8fbd524621cdcb', 16),
                                index = 0
                            ),
                            script = bytes_to_data([71, 48, 68, 2, 32, 80, 225, 63, 52, 132, 228, 124, 240, 95, 42, 165, 46, 150, 43, 36, 242, 47, 251, 5, 143, 241, 38, 168, 221, 181, 11, 81, 87, 13, 73, 10, 236, 2, 32, 81, 223, 167, 229, 20, 96, 248, 219, 8, 164, 39, 186, 101, 78, 96, 82, 212, 146, 185, 186, 247, 66, 178, 241, 148, 171, 255, 254, 208, 114, 122, 41, 1, 33, 3, 121, 83, 98, 152, 35, 127, 209, 217, 37, 49, 1, 223, 182, 5, 99, 50, 61, 211, 144, 248, 195, 103, 8, 174, 67, 244, 76, 6, 229, 151, 33, 30]),
                            sequence = 4294967294
                        )
                    ],
                    tx_outs = [
                        dict(
                            value = 30000000,
                            script = bytes_to_data([ 118, 169, 20, 106, 8, 40, 36, 103, 106, 143, 84, 149, 179, 250, 233, 207, 37, 131, 122, 136, 58, 115, 1, 136, 172 ])
                        ),
                        dict(
                            value = 91024511644,
                            script = bytes_to_data([118, 169, 20, 172, 6, 156, 107, 16, 133, 34, 25, 141, 47, 231, 209, 201, 95, 208, 104, 102, 188, 183, 186, 136, 172])
                        )
                    ],
                    lock_time = 16518944
                )
            ],
            transaction_fees = [ 22655 ],
            merkle_link = dict(
                branch = [],
                index = 0
            ),
            subsidy = 41082666040,
            last_update = 1674480469
        )
        return res
    
    def __init__(self, net, tracker, p2p_node):

        self.net = net
        self.tracker = tracker
        self.p2p_node = p2p_node

        self.bitcoind_work = variable.Variable(self.get_fake_bitcoind_work())
        self.best_block_header = variable.Variable(None)
        self.best_share_var = variable.Variable(best)

        self.mining2_txs_var = variable.Variable({})
    #     self.best_block_header = variable.Variable({
    #         ('version', pack.IntType(32)),
    # ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
    # ('merkle_root', pack.IntType(256)),
    # ('timestamp', pack.IntType(32)),
    # ('bits', FloatingIntegerType()),
    # ('nonce', pack.IntType(32)),
    #     })
    

p2p_node = FakeP2PNode()
coind_node = FakeCoindNode(net, tracker, p2p_node)

address = 'DKCJJSrA9vAXwwbzTbD2PL3553iKX3oPv1'
my_pubkey_hash = coind_data.address_to_pubkey_hash(address, net.PARENT)
pubkeys = coind_data.address_to_pubkey_hash(address, net.PARENT)

wb = work.WorkerBridge(coind_node, my_pubkey_hash, donation_percentage, 0, pubkeys)
_user, _pubkey_hash, _desired_share_target, _desired_pseudoshare_target = wb.preprocess_request('user:pass')
print('user: {0}, pubkey_hash : {1}, desired_share_target: {2}, desired_pseudoshare_target: {3}'.format(_user, _pubkey_hash, _desired_share_target, _desired_pseudoshare_target))
# wb.get_work()

ba, got_response = wb.get_work(_pubkey_hash, _desired_share_target, _desired_pseudoshare_target)

print(ba)

c2pool_coinb1 = bytes_to_data([1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 4, 36, 15, 252, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 6, 106, 36, 170, 33, 169, 237, 33, 124, 15, 0, 0, 0, 0, 0, 25, 118, 169, 20, 154, 44, 211, 193, 49, 0, 103, 174, 126, 71, 167, 134, 155, 51, 13, 48, 182, 145, 198, 27, 136, 172, 228, 69, 210, 11, 0, 0, 0, 0, 25, 118, 169, 20, 208, 230, 206, 121, 50, 250, 194, 135, 15, 183, 85, 220, 74, 170, 149, 134, 122, 214, 236, 120, 136, 172, 137, 247, 233, 59, 0, 0, 0, 0, 25, 118, 169, 20, 187, 53, 31, 201, 251, 189, 142, 31, 64, 148, 33, 48, 231, 113, 49, 151, 141, 246, 222, 65, 136, 172, 74, 225, 122, 244, 8, 0, 0, 0, 169, 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174, 0, 0, 0, 0, 0, 0, 0, 0, 42, 106, 40, 3, 7, 247, 8, 138, 69, 160, 128, 161, 176, 140, 58, 79, 73, 209, 107, 204, 149, 69, 118, 154, 207, 84, 88, 29, 110, 224, 84, 135, 45, 227, 200])
print(c2pool_coinb1)
print([ord(x) for x in ba['coinb1']])

#c2pool: [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 4, 36, 15, 252, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 6, 106, 36, 170, 33, 169, 237, 33, 124, 15, 0, 0, 0, 0, 0, 25, 118, 169, 20, 154, 44, 211, 193, 49, 0, 103, 174, 126, 71, 167, 134, 155, 51, 13, 48, 182, 145, 198, 27, 136, 172, 228, 69, 210, 11, 0, 0, 0, 0, 25, 118, 169, 20, 208, 230, 206, 121, 50, 250, 194, 135, 15, 183, 85, 220, 74, 170, 149, 134, 122, 214, 236, 120, 136, 172, 137, 247, 233, 59, 0, 0, 0, 0, 25, 118, 169, 20, 187, 53, 31, 201, 251, 189, 142, 31, 64, 148, 33, 48, 231, 113, 49, 151, 141, 246, 222, 65, 136, 172, 74, 225, 122, 244, 8, 0, 0, 0, 169, 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174, 0, 0, 0, 0, 0, 0, 0, 0, 42, 106, 40, 3, 7, 247, 8, 138, 69, 160, 128, 161, 176, 140, 58, 79, 73, 209, 107, 204, 149, 69, 118, 154, 207, 84, 88, 29, 110, 224, 84, 135, 45, 227, 200]
#p2pool: [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 5, 4, 36, 15, 252, 0, 255, 255, 255, 255, 6, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 158, 225, 45, 180, 212, 112, 57, 176, 71, 61, 146, 195, 190, 91, 100, 45, 246, 111, 181, 94, 193, 65, 221, 159, 190, 97, 206, 213, 55, 249, 167, 146, 179, 19, 117, 2, 0, 0, 0, 0, 25, 118, 169, 20, 154, 44, 211, 193, 49, 0, 103, 174, 126, 71, 167, 134, 155, 51, 13, 48, 182, 145, 198, 27, 136, 172, 210, 91, 62, 12, 0, 0, 0, 0, 25, 118, 169, 20, 208, 230, 206, 121, 50, 250, 194, 135, 15, 183, 85, 220, 74, 170, 149, 134, 122, 214, 236, 120, 136, 172, 177, 76, 4, 130, 9, 0, 0, 0, 25, 118, 169, 20, 187, 53, 31, 201, 251, 189, 142, 31, 64, 148, 33, 48, 231, 113, 49, 151, 141, 246, 222, 65, 136, 172, 2, 0, 0, 0, 0, 0, 0, 0, 169, 82, 33, 3, 138, 184, 47, 58, 79, 86, 156, 69, 113, 196, 131, 213, 103, 41, 232, 51, 153, 121, 91, 173, 179, 40, 33, 202, 182, 77, 4, 231, 181, 209, 6, 134, 65, 4, 255, 208, 61, 228, 74, 110, 17, 185, 145, 127, 58, 41, 249, 68, 50, 131, 217, 135, 28, 157, 116, 62, 243, 13, 94, 221, 205, 55, 9, 75, 100, 209, 179, 216, 9, 4, 150, 181, 50, 86, 120, 107, 245, 200, 41, 50, 236, 35, 195, 183, 77, 159, 5, 166, 249, 90, 139, 85, 41, 53, 38, 86, 102, 75, 65, 4, 87, 163, 55, 184, 101, 87, 245, 177, 92, 148, 84, 74, 210, 103, 249, 106, 88, 45, 194, 185, 30, 104, 115, 150, 143, 247, 186, 23, 79, 218, 104, 116, 175, 151, 156, 217, 175, 65, 236, 32, 50, 223, 223, 214, 88, 123, 229, 177, 74, 67, 85, 84, 109, 84, 19, 136, 195, 241, 85, 90, 103, 209, 28, 45, 83, 174, 0, 0, 0, 0, 0, 0, 0, 0, 42, 106, 40, 12, 235, 36, 243, 44, 181, 178, 239, 225, 19, 153, 241, 10, 138, 33, 141, 75, 244, 254, 85, 25, 122, 146, 55, 126, 100, 61, 176, 122, 111, 103, 241]
