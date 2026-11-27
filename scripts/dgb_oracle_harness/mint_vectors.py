#!/usr/bin/env python2
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mint V35 shares with the python DGB oracle, for c2pool-dgb's verifier.

usage: mint_vectors.py ORACLE_DIR OUT_JSON

The python -> c2pool direction of the harness (check_vectors.py is the
other). ORACLE_DIR is a read-only checkout of frstrtr/p2pool-dgb-scrypt
(22761e7) whose root is the p2pool package. Every share is built by the
oracle's own Share.generate_transaction / get_share on a genesis-rooted
tracker (the path work.py takes for a miner's share), checked with
Share.check, and written packed (as_share) with its hash and generation
transaction. Payout addresses rotate through the cases python accepts and
c2pool must verify byte-exact: base58 P2PKH and P2SH, lowercase and
UPPERCASE bech32, a witness-v1 address of the same program, 32-byte and
31-byte programs with a leading 0x00, and the donation's own P2PKH address.

Negatives are valid shares mutated so python refuses them (each is checked
here to be refused): a whitespace address, the segwit_data none-value, and
far_share_hash / absheight / abswork changed. c2pool must refuse them too.
PoW is not under test: POW_FUNC is replaced by 0. Needs python 2.7 and
twisted. Exit status 0 when every share and negative behaved in python.
"""
import json
import os
import random
import sys
import tempfile

# Share donations (review 7a4373856 R1): --give-author's 66, none, split
# jobs (32768), the extremes.
DONATIONS = [0, 66, 32768, 65535, 32768, 7]

ADDRESSES = [
    'DB68diZto76gixVajwyoMjcEXsSdyEhnS9',                                   # base58 P2PKH
    'SdasP9NHJS5wW5AwADre1ozLhHkeUU6Qqx',                                   # base58 P2SH
    'dgb1q24242424242424242424242424242424swqgq4',                          # bech32 v0, 20 bytes
    'DGB1Q24242424242424242424242424242424SWQGQ4',                          # the same, UPPERCASE
    'dgb1p24242424242424242424242424242424mshrd7',                          # witness v1, same program
    'dgb1qqpnxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenqtstmfg',      # 32 bytes, leading 0x00
    'dgb1pvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvc5glslh',        # 31 bytes, witness v1
    'DQ8AwqR2XJE9G5dSEfspJYH7Spre85dj6L',                                   # the donation's own P2PKH
]


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    oracle = os.path.abspath(sys.argv[1])
    out_path = sys.argv[2]

    pkg_dir = tempfile.mkdtemp(prefix='dgb-oracle-pkg-')
    os.symlink(oracle, os.path.join(pkg_dir, 'p2pool'))
    sys.path.insert(0, pkg_dir)
    import p2pool
    p2pool.DEBUG = False
    p2pool.BENCH = False
    from p2pool import data as p2pool_data
    from p2pool import networks
    from p2pool.bitcoin import data as bitcoin_data

    net = networks.nets['digibyte']
    net.PARENT.POW_FUNC = lambda header: 0
    net.PARENT.padding_bugfix = True
    tracker = p2pool_data.OkayTracker(net)
    Share = p2pool_data.Share
    share_type = Share.get_dynamic_types(net)['share_type']
    rnd = random.Random(20261127)

    block_bits = bitcoin_data.FloatingInteger(0x1b0404cb)
    # An empty block (no transactions): work.py's segwit_data for it.
    segwit_data = dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=0)
    t0 = 1790000000
    shares, records, negatives = [], [], []
    fails = 0

    def mint(i, address):
        prev = shares[-1] if shares else None
        share_data = dict(
            previous_share_hash=prev.hash if prev is not None else None,
            coinbase='\x03' + chr(i % 256) + '\x01\x02' + 'c2pool-dgb-harness',
            nonce=rnd.getrandbits(32),
            address=address,
            subsidy=72000 * 10**8,
            donation=DONATIONS[i % len(DONATIONS)],
            stale_info=None,
            desired_version=35,
        )
        gap = 15 if i % 9 else 1 + i % 7
        desired_timestamp = (prev.timestamp + gap) if prev is not None else t0
        last_txout_nonce = rnd.getrandbits(64)
        share_info, gentx, other_tx_hashes, get_share = Share.generate_transaction(
            tracker, share_data, block_bits.target, desired_timestamp, 2**256 - 1,
            dict(branch=[], index=0), [], net, known_txs=None,
            last_txout_nonce=last_txout_nonce, segwit_data=segwit_data)
        header = dict(
            version=0x20000002,   # Scrypt algo bits
            previous_block=rnd.getrandbits(256),
            merkle_root=bitcoin_data.check_merkle_link(
                bitcoin_data.hash256(bitcoin_data.tx_id_type.pack(gentx)), dict(branch=[], index=0)),
            timestamp=share_info['timestamp'],
            bits=block_bits,
            nonce=rnd.getrandbits(32),
        )
        share = get_share(header, last_txout_nonce)
        return share, gentx

    def packed(share):
        s = share.as_share()
        return dict(type=s['type'], contents=s['contents'].encode('hex'))

    def refused(contents_hex, typ, tracker_):
        try:
            sh = p2pool_data.load_share(dict(type=typ, contents=contents_hex.decode('hex')), net, None)
            sh.check(tracker_)
            return None
        except Exception as e:
            return '%s(%r)' % (type(e).__name__, str(e))

    def mutate(share, fn):
        c = share_type.unpack(share.as_share()['contents'])
        fn(c)
        return share_type.pack(c).encode('hex')

    n = 130   # past TARGET_LOOKBEHIND: the retarget and its clip are compared too
    for i in range(n):
        address = ADDRESSES[i % len(ADDRESSES)]
        # Negatives against the tracker before share i (python must refuse).
        if shares and i in (5, 12, 19, 110):
            base = shares[-1]
            # A next share built on base, then mutated (not added).
            cand, _ = mint(i, ADDRESSES[0])
            for name, fn in [
                ('whitespace address', lambda c: c['share_info']['share_data'].__setitem__('address', ' ' + ADDRESSES[0])),
                ('trailing newline address', lambda c: c['share_info']['share_data'].__setitem__('address', ADDRESSES[0] + '\n')),
                ('segwit_data none-value', lambda c: c['share_info'].__setitem__('segwit_data', None)),
                ('far_share_hash', lambda c: c['share_info'].__setitem__('far_share_hash', 0x1234)),
                ('absheight+1', lambda c: c['share_info'].__setitem__('absheight', c['share_info']['absheight'] + 1)),
                ('abswork+1', lambda c: c['share_info'].__setitem__('abswork', c['share_info']['abswork'] + 1)),
            ]:
                hexc = mutate(cand, fn)
                why = refused(hexc, 35, tracker)
                if why is None:
                    print 'FAIL negative %r before %d: python ACCEPTED it' % (name, i)
                    fails += 1
                else:
                    print 'ok   negative %r before %d: python refused: %s' % (name, i, why[:90])
                negatives.append(dict(name=name, before=i, type=35, contents=hexc, python_refusal=why))
        share, gentx = mint(i, address)
        why = refused(packed(share)['contents'], 35, tracker)
        if why is not None:
            print 'FAIL share %d (%s): python refused its own share: %s' % (i, address, why)
            fails += 1
        tracker.add(share)
        shares.append(share)
        rec = packed(share)
        rec.update(index=i, address=address, hash='%064x' % share.hash,
                   gentx=bitcoin_data.tx_id_type.pack(gentx).encode('hex'))
        records.append(rec)
        print 'ok   share %d %016x %s' % (i, share.hash >> 192, address)

    json.dump(dict(oracle='frstrtr/p2pool-dgb-scrypt 22761e7', shares=records, negatives=negatives),
              open(out_path, 'w'), indent=1)
    print 'RESULT %s shares=%d negatives=%d fails=%d' % ('PASS' if fails == 0 else 'FAIL', len(records),
                                                         len(negatives), fails)
    return 0 if fails == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
