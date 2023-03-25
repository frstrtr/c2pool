import data
import net as _net
import coind_data
import pack
import share
import p2pool_math

def hex_to_bytes(_hex):
    return ''.join(chr(int(_hex[i:i+2], 16)) for i in range(0, len(_hex), 2))

def bytes_to_data(bytes):
    res = b''
    for x in bytes:
        res += chr(x)
    return res #str(res).replace(', ', ' ')


net = _net

DONATION_SCRIPT = '5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae'.decode('hex')
gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]
print('gentx_before_refhash = {0}'.format([ord(x) for x in gentx_before_refhash]))

#contents=========
segwit_activated = True

contents = dict(
    min_header = dict(
            version=536870914,
            previous_block = int('c0979d26dd46ec1a95fbc55b37865bd7a8365d74bc5c06214354ca833356a719', 16),
            timestamp = 1679235245,
            bits = pack.FloatingInteger(453035081),
            nonce = 2367031696
        ),
    share_info = dict(
            share_data = dict(
                previous_share_hash = None,
                coinbase = bytes_to_data([4, 189, 232, 0, 1, 0]),
                nonce = 1170798674,
                pubkey_hash = int('78ecd67a8695aa4adc55b70f87c2fa3279cee6d0', 16),
                subsidy = 40624161389,
                donation = 0,
                stale_info = None,
                desired_version = 17
            ),
            far_share_hash = None,
            max_bits = pack.FloatingInteger(504365055),
            bits = pack.FloatingInteger(504365055),
            timestamp = 1679235200,
            new_transaction_hashes = [int('bb8dd34961460ce315a67e6365a18517f363d23504fb9fd493f6d6c78b76c02f', 16)],
            transaction_hash_refs = [0,0],
            absheight = 1,
            abswork = int('00000000000000000000000000100001', 16),
            segwit_data = dict(
                txid_merkle_link = dict(
                    branch = [int('bb8dd34961460ce315a67e6365a18517f363d23504fb9fd493f6d6c78b76c02f', 16)],
                    index = 0
                ),
                wtxid_merkle_root = int('f8bc0a96c3cb4082b39719a7e425c3376a414ea8f5d51a77d6659a2c484d3f24', 16)
            )
        ),
    hash_link = dict(
            state = bytes_to_data([106, 65, 85, 198, 195, 49, 27, 195, 225, 154, 118, 231, 114, 112, 22, 35, 156, 134, 185, 137, 6, 51, 179, 26, 35, 159, 150, 97, 195, 97, 173, 227]),
            extra_data = '',
            length = 323
        ),
    ref_merkle_link = dict(
            branch = [],
            index = 0
        ),
    last_txout_nonce = 1
)


#var==============

min_header = contents['min_header']
share_info = contents['share_info']
hash_link = contents['hash_link']


gentx_hash = data.check_hash_link(
            hash_link,
            share.Share.get_ref_hash(net, share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(contents['last_txout_nonce']) + pack.IntType(32).pack(0),
            gentx_before_refhash,
        )

merkle_root = coind_data.check_merkle_link(gentx_hash, share_info['segwit_data']['txid_merkle_link'] if segwit_activated else merkle_link)
header = dict(min_header, merkle_root=merkle_root)
pow_hash = net.PARENT.POW_FUNC(coind_data.block_header_type.pack(header))
# pow_hash = int('b5ddc8da337444da59cb76564364ca33bc20d9ed98aeadf884995d4787add7e1', 16)
target = int('00000fffff000000000000000000000000000000000000000000000000000000', 16) #+

#=======================

desired_share_target = None

if desired_share_target is None:
            desired_share_target = coind_data.difficulty_to_target(float(1.0 / net.PARENT.DUMB_SCRYPT_DIFF))
            # local_hash_rate = local_addr_rates.get(pubkey_hash, 0)
            local_hash_rate = 0
            if local_hash_rate > 0.0:
                desired_share_target = min(desired_share_target,
                    coind_data.average_attempts_to_target(local_hash_rate * net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
            
            lookbehind = 3600//net.SHARE_PERIOD
            # block_subsidy = self.node.bitcoind_work.value['subsidy']
            block_subsidy = 40624176735
            previous_share = None
            if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
                expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
                    * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
                if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
                    desired_share_target = min(desired_share_target,
                        bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
                    )

print('desired_share_target = {0}'.format(hex(desired_share_target)))
pre_target3 = net.MAX_TARGET
bits = pack.FloatingInteger.from_target_upper_bound(p2pool_math.clip(desired_share_target, (pre_target3//30, pre_target3)))
desired_pseudoshare_target = None
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
            pack.FloatingInteger(444073888).target)*net.SPREAD)*net.PARENT.DUST_THRESHOLD/block_subsidy))
else:
    target = desired_pseudoshare_target
print('TARGET = {0}'.format(hex(target)))
# target = max(target, bits.target)
target = p2pool_math.clip(target, net.PARENT.SANE_TARGET_RANGE)

print('bits.target = {0}'.format(hex(bits.target)))
print(hex(p2pool_math.clip(bits.target, net.PARENT.SANE_TARGET_RANGE)))
print('target = {0}'.format(hex(target)))
#=======================

if not (2 <= len(share_info['share_data']['coinbase']) <= 100):
            raise ValueError('''bad coinbase size! %i bytes''' % (len(share_info['share_data']['coinbase']),))
        
        
assert not hash_link['extra_data'], repr(hash_link['extra_data'])

####################
# #(BlockHeaderType: version = 536870914, previous_block = 673223d725ea62478d6af3a8bef70f82f17c9947f2e0bd0703ee526aa1c1e532, timestamp = 1678723531, bits = 453059241, nonce = 3769764432, merkle_root = 4fb6cf87cb7fa90044d998311236ac19b1c3a489e3f1c9f85d25080b0b539d5f)
# _header = dict(
#     version = 536870914,
#     previous_block = int('673223d725ea62478d6af3a8bef70f82f17c9947f2e0bd0703ee526aa1c1e532', 16),
#     timestamp = 1678723531,
#     bits = pack.FloatingInteger(453059241), 
#     nonce = 3769764432, 
#     merkle_root = int('4fb6cf87cb7fa90044d998311236ac19b1c3a489e3f1c9f85d25080b0b539d5f', 16)
# )

# print('_header pow = {0}'.format(hex(net.PARENT.POW_FUNC(coind_data.block_header_type.pack(_header)))))
      
# # _merkle_root = dict(
      
# # )
# # _header = dict(_min_header, merkle_root=_merkle_root)
# ##############

# #(TxType: version = 1, tx_ins = [ (TxInType: previous_output = (PreviousOutput: hash = 5780ce9d686c8f1c9ac1cc0b4a2525125b41bcf1638497aedca84b44e2213dbd, index = 1), script = [ 22 0 20 177 252 118 46 112 139 199 93 194 106 130 82 185 3 21 84 7 136 186 66 ], sequence = 4294967294) ], tx_outs = [ (TxOutType: value = 142567699, script = [ 169 20 6 113 157 28 123 115 94 166 43 3 204 102 5 193 64 146 44 232 185 163 135 ]) (TxOutType: value = 150000000, script = [ 0 20 193 56 40 131 24 72 177 234 190 44 85 163 212 173 216 162 190 103 149 191 ]) ], lock_time = 16804495, wdata = (WitnessTransactionData: marker = 0, flag = 1, witness = [ [ [ 48 68 2 32 98 167 219 205 197 203 132 76 68 253 244 106 18 151 248 237 73 49 156 255 110 234 173 6 114 58 33 109 148 176 75 144 2 32 9 195 252 254 232 89 152 183 172 245 134 59 101 223 38 213 203 87 112 253 166 209 251 188 81 127 176 205 107 227 14 214 1 ][ 3 236 104 76 71 2 66 102 79 255 13 252 201 16 121 161 128 113 189 12 234 121 206 90 100 251 88 200 216 79 254 45 247 ]]]))
# # dict(
# #   version = 1,
# #   tx_ins = [
# #       dict(
# #           previous_output = dict(
# #               hash = int('46683430f87c6ceb23628e0a1908438b3288f256218acef83b8fbd524621cdcb', 16),
# #               index = 0
# #           ),
# #           script = bytes_to_data([71, 48, 68, 2, 32, 80, 225, 63, 52, 132, 228, 124, 240, 95, 42, 165, 46, 150, 43, 36, 242, 47, 251, 5, 143, 241, 38, 168, 221, 181, 11, 81, 87, 13, 73, 10, 236, 2, 32, 81, 223, 167, 229, 20, 96, 248, 219, 8, 164, 39, 186, 101, 78, 96, 82, 212, 146, 185, 186, 247, 66, 178, 241, 148, 171, 255, 254, 208, 114, 122, 41, 1, 33, 3, 121, 83, 98, 152, 35, 127, 209, 217, 37, 49, 1, 223, 182, 5, 99, 50, 61, 211, 144, 248, 195, 103, 8, 174, 67, 244, 76, 6, 229, 151, 33, 30]),
# #           sequence = 4294967294
# #       )
# #   ],
# #   tx_outs = [
# #       dict(
# #           value = 30000000,
# #           script = bytes_to_data([ 118, 169, 20, 106, 8, 40, 36, 103, 106, 143, 84, 149, 179, 250, 233, 207, 37, 131, 122, 136, 58, 115, 1, 136, 172 ])
# #       ),
# #       dict(
# #           value = 91024511644,
# #           script = bytes_to_data([118, 169, 20, 172, 6, 156, 107, 16, 133, 34, 25, 141, 47, 231, 209, 201, 95, 208, 104, 102, 188, 183, 186, 136, 172])
# #       )
# #   ],
# #   lock_time = 16518944
# # )
# known_txs = {
#     int('352d8e2d5faa0e9b8b7b3926ed78e67da7cc2f1029085bbe0129b0a85f36c936', 16):
#     dict(
#         version = 1,
#         tx_ins = [
#             dict(
#                 previous_output = dict(
#                     hash = int('5780ce9d686c8f1c9ac1cc0b4a2525125b41bcf1638497aedca84b44e2213dbd', 16),
#                     index = 1
#                 ),
#                 script = bytes_to_data([22, 0, 20, 177, 252, 118, 46, 112, 139, 199, 93, 194, 106, 130, 82, 185, 3, 21, 84, 7, 136, 186, 66]),
#                 sequence = 4294967294
#             )
#         ],
#         tx_outs = [
#             dict(
#                 value = 142567699,
#                 script = bytes_to_data([169, 20, 6, 113, 157, 28, 123, 115, 94, 166, 43, 3, 204, 102, 5, 193, 64, 146, 44, 232, 185, 163, 135])
#             ),
#             dict(
#                 value = 150000000,
#                 script = bytes_to_data([0, 20, 193, 56, 40, 131, 24, 72, 177, 234, 190, 44, 85, 163, 212, 173, 216, 162, 190, 103, 149, 191])
#             )
#         ],
#         lock_time = 16804495,
#         marker = 0,
#         flag = 1,
#         witness = [[bytes_to_data([48, 68, 2, 32, 98, 167, 219, 205, 197, 203, 132, 76, 68, 253, 244, 106, 18, 151, 248, 237, 73, 49, 156, 255, 110, 234, 173, 6, 114, 58, 33, 109, 148, 176, 75, 144, 2, 32, 9, 195, 252, 254, 232, 89, 152, 183, 172, 245, 134, 59, 101, 223, 38, 213, 203, 87, 112, 253, 166, 209, 251, 188, 81, 127, 176, 205, 107, 227, 14, 214, 1]), bytes_to_data([3, 236, 104, 76, 71, 2, 66, 102, 79, 255, 13, 252, 201, 16, 121, 161, 128, 113, 189, 12, 234, 121, 206, 90, 100, 251, 88, 200, 216, 79, 254, 45, 247])]]
#     )
# }

# other_transaction_hashes = [int('352d8e2d5faa0e9b8b7b3926ed78e67da7cc2f1029085bbe0129b0a85f36c936', 16)]

# share_txs = [(known_txs[h], coind_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
# segwit_data = dict(txid_merkle_link=coind_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=coind_data.merkle_hash([0] + [coind_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))

# print(segwit_data)

# # _segwit_data1 = dict()
# # _segwit_data2 = dict()


# __gentx_hash = int("e63b9f78cbc9a9d6749bd79b961699afae50f23a4054f5b0202a1d4dff0370f7", 16)
# __merkle_link = dict(branch = [int("66102b718408d8da8fed1bf04438f881a67c35e12aba341a30ae7e8d5bd64f15", 16), int("06da12f71256344a9fe06c07119727a81bfbeb9e0f04f7fd1fb315f935983e73", 16)], index=0)

# __merkle_root = coind_data.check_merkle_link(__gentx_hash, __merkle_link)
# print("__MERKLE_ROOT = {0}".format(hex(__merkle_root)))


####################

print(hex(target))
print('pow_hash = {0}'.format(hex(pow_hash)))
if pow_hash > target:
    raise Exception('share PoW invalid')
else:
    print("TRUE POW")