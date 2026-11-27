#!/usr/bin/env python2
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run c2pool-dgb V35 share vectors through the python DGB oracle.

usage: check_vectors.py ORACLE_DIR VECTORS_JSON

ORACLE_DIR   a checkout of frstrtr/p2pool-dgb-scrypt (22761e7); its root is
             the p2pool package itself.
VECTORS_JSON written by dgb_work_source_test
             --gtest_filter=DgbOracleVectors.* with DGB_ORACLE_VECTORS=<file>.

Every share is loaded with the oracle's load_share, checked with Share.check
against a tracker holding the shares before it, and its generation transaction
rebuilt by the same generate_transaction call check() makes; the bytes
must equal c2pool's. Every negative (a mutated share) must be rejected.
PoW is not under test: POW_FUNC is replaced by 0 (the vectors are not mined).
Needs python 2.7 and twisted. Exit status 0 = PASS.
"""
import json
import os
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    oracle = os.path.abspath(sys.argv[1])
    vectors = json.load(open(sys.argv[2]))

    # The oracle tree's root is the package: expose it as 'p2pool'.
    pkg_dir = tempfile.mkdtemp(prefix='dgb-oracle-pkg-')
    os.symlink(oracle, os.path.join(pkg_dir, 'p2pool'))
    sys.path.insert(0, pkg_dir)

    # main.py sets these from its arguments; the oracle's code reads them.
    import p2pool
    p2pool.DEBUG = False
    p2pool.BENCH = False

    from p2pool import data as p2pool_data
    from p2pool import networks
    from p2pool.bitcoin import data as bitcoin_data

    net = networks.nets['digibyte']
    net.PARENT.POW_FUNC = lambda header: 0
    tracker = p2pool_data.OkayTracker(net)

    def load(v):
        return p2pool_data.load_share(dict(type=v['type'], contents=v['contents'].decode('hex')), net, None)

    def regen_gentx(share):
        _, gentx, _, _ = share.generate_transaction(
            tracker, share.share_info['share_data'], share.header['bits'].target,
            share.share_info['timestamp'], share.share_info['bits'].target,
            share.contents['ref_merkle_link'], [], net, known_txs=None,
            last_txout_nonce=share.contents['last_txout_nonce'],
            segwit_data=share.share_info.get('segwit_data', None))
        return bitcoin_data.tx_id_type.pack(gentx).encode('hex')

    negatives = {}
    for n in vectors.get('negatives', []):
        negatives.setdefault(n['before'], []).append(n)

    fails = 0
    checked = 0
    rejected = 0
    for k, v in enumerate(vectors['shares']):
        for n in negatives.get(k, []):
            # Each negative touches only share_info: python must reject it in
            # check() with ValueError('share_info invalid'), not elsewhere.
            try:
                load(n).check(tracker)
                print 'FAIL negative %r before share %d was ACCEPTED' % (n['name'], k)
                fails += 1
            except ValueError as e:
                if str(e) == 'share_info invalid':
                    print 'ok   negative %r before share %d rejected: share_info invalid' % (n['name'], k)
                    rejected += 1
                else:
                    print 'FAIL negative %r before share %d rejected for another reason: %r' % (n['name'], k, e)
                    fails += 1
            except Exception as e:
                print 'FAIL negative %r before share %d rejected for another reason: %r' % (n['name'], k, e)
                fails += 1
        try:
            share = load(v)
        except Exception as e:
            print 'FAIL share %d does not load: %r' % (k, e)
            fails += 1
            break
        if '%064x' % share.hash != v['hash']:
            print 'FAIL share %d hash python=%064x c2pool=%s' % (k, share.hash, v['hash'])
            fails += 1
        try:
            share.check(tracker)
            ok = True
        except Exception as e:
            print 'FAIL share %d (%s) rejected: %r' % (k, v.get('address', ''), e)
            fails += 1
            ok = False
        try:
            g = regen_gentx(share)
            if g != v['gentx']:
                print 'FAIL share %d gentx differs' % k
                print '  python ' + g
                print '  c2pool ' + v['gentx']
                fails += 1
                ok = False
        except Exception as e:
            print 'FAIL share %d gentx not regenerated: %r' % (k, e)
            fails += 1
            ok = False
        if ok:
            print 'ok   share %d %s %s' % (k, v['hash'][:16], v.get('address', ''))
        checked += 1
        tracker.add(share)

    print 'RESULT %s shares=%d negatives_rejected=%d/%d fails=%d oracle=%s' % (
        'PASS' if fails == 0 else 'FAIL', checked, rejected,
        sum(len(x) for x in negatives.values()), fails, vectors.get('oracle', '?'))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
