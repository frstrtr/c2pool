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

#contents=========
segwit_activated = True

contents = dict(
    min_header = dict(
            version=536870914,
            previous_block = int('3cd541e0fb12501507a2fe7dafdc172ccb712562047a54123365e25e18d3c980', 16),
            timestamp = 1678542857,
            bits = pack.FloatingInteger(453028810),
            nonce = 3643410592
        ),
    share_info = dict(
            share_data = dict(
                previous_share_hash = None,
                coinbase = bytes_to_data([4, 231, 51, 0, 1, 0]),
                nonce = 2674057906,
                pubkey_hash = int('78ecd67a8695aa4adc55b70f87c2fa3279cee6d0', 16),
                subsidy = 40624161389,
                donation = 0,
                stale_info = None,
                desired_version = 17
            ),
            far_share_hash = None,
            max_bits = pack.FloatingInteger(504365055),
            bits = pack.FloatingInteger(504365055),
            timestamp = 1678542848,
            new_transaction_hashes = [int('978f2d0805eacaa6a74ba979d4754128c5252822d358788546826b41120b10f5', 16)],
            transaction_hash_refs = [0,0],
            absheight = 1,
            abswork = int('00000000000000000000000000100001', 16),
            segwit_data = dict(
                txid_merkle_link = dict(
                    branch = [int('0000000000000000000000000000000000000000000000000000000000000000', 16), int('905172d6bcd8823258021f855ce65822dcb22492507345f3f8755f20362b163b', 16)],
                    index = 0
                ),
                wtxid_merkle_root = int('70145277e385f9d16d620c118dd8a24e795f332a8df88dd73f6b8deaa2dbe3eb', 16)
            )
        ),
    hash_link = dict(
            state = bytes_to_data([8, 144, 15, 26, 59, 250, 72, 69, 209, 136, 250, 62, 24, 17, 38, 198, 83, 6, 48, 212, 248, 147, 210, 157, 146, 255, 45, 182, 44, 124, 0, 144]),
            extra_data = '',
            length = 323
        ),
    ref_merkle_link = dict(
            branch = [],
            index = 0
        ),
    last_txout_nonce = 3
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

print('bits.target = {0}'.format(hex(bits.target)))
#=======================

if not (2 <= len(share_info['share_data']['coinbase']) <= 100):
            raise ValueError('''bad coinbase size! %i bytes''' % (len(share_info['share_data']['coinbase']),))
        
        
assert not hash_link['extra_data'], repr(hash_link['extra_data'])

print('pow_hash = {0}'.format(hex(pow_hash)))
if pow_hash > target:
    raise Exception('share PoW invalid')
else:
    print("TRUE POW")