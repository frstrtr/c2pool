import data
import pack
import time
import p2pool_math as math
import coind_data
import array

DONATION_SCRIPT = '5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae'.decode('hex')

def is_segwit_activated(version, net):
    assert not(version is None or net is None)
    segwit_activation_version = getattr(net, 'SEGWIT_ACTIVATION_VERSION', 0)
    return version >= segwit_activation_version and segwit_activation_version > 0

class BaseShare(object):
    VERSION = 0
    VOTING_VERSION = 0
    SUCCESSOR = None
    
    small_block_header_type = pack.ComposedType([
        ('version', pack.VarIntType()),
        ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
        ('timestamp', pack.IntType(32)),
        ('bits', pack.FloatingIntegerType()),
        ('nonce', pack.IntType(32)),
    ])
    share_info_type = None
    share_type = None
    ref_type = None

    gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

    gentx_size = 50000 # conservative estimate, will be overwritten during execution
    gentx_weight = 200000
    cached_types = None
    @classmethod
    def get_dynamic_types(cls, net):
        if not cls.cached_types == None:
            return cls.cached_types
        t = dict(share_info_type=None, share_type=None, ref_type=None)
        segwit_data = ('segwit_data', pack.PossiblyNoneType(dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=2**256-1), pack.ComposedType([
            ('txid_merkle_link', pack.ComposedType([
                ('branch', pack.ListType(pack.IntType(256))),
                ('index', pack.IntType(0)), # it will always be 0
            ])),
            ('wtxid_merkle_root', pack.IntType(256))
        ])))
        t['share_info_type'] = pack.ComposedType([
            ('share_data', pack.ComposedType([
                ('previous_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
                ('coinbase', pack.VarStrType()),
                ('nonce', pack.IntType(32)),
                ('pubkey_hash', pack.IntType(160)),
                ('subsidy', pack.IntType(64)),
                ('donation', pack.IntType(16)),
                ('stale_info', pack.EnumType(pack.IntType(8), dict((k, {0: None, 253: 'orphan', 254: 'doa'}.get(k, 'unk%i' % (k,))) for k in xrange(256)))),
                ('desired_version', pack.VarIntType()),
            ]))] + ([segwit_data] if is_segwit_activated(cls.VERSION, net) else []) + [
            ('new_transaction_hashes', pack.ListType(pack.IntType(256))),
            ('transaction_hash_refs', pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
            ('far_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
            ('max_bits', pack.FloatingIntegerType()),
            ('bits', pack.FloatingIntegerType()),
            ('timestamp', pack.IntType(32)),
            ('absheight', pack.IntType(32)),
            ('abswork', pack.IntType(128)),
        ])
        t['share_type'] = pack.ComposedType([
            ('min_header', cls.small_block_header_type),
            ('share_info', t['share_info_type']),
            ('ref_merkle_link', pack.ComposedType([
                ('branch', pack.ListType(pack.IntType(256))),
                ('index', pack.IntType(0)),
            ])),
            ('last_txout_nonce', pack.IntType(64)),
            ('hash_link', data.hash_link_type),
            ('merkle_link', pack.ComposedType([
                ('branch', pack.ListType(pack.IntType(256))),
                ('index', pack.IntType(0)), # it will always be 0
            ])),
        ])
        t['ref_type'] = pack.ComposedType([
            ('identifier', pack.FixedStrType(64//8)),
            ('share_info', t['share_info_type']),
        ])
        cls.cached_types = t
        return t

    @classmethod
    def generate_transaction(cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None):
        t0 = time.time()
        previous_share = tracker.items[share_data['previous_share_hash']] if share_data['previous_share_hash'] is not None else None
        
        height, last = tracker.get_height_and_last(share_data['previous_share_hash'])
        print('{0}, {1}, {2}'.format(height, net.REAL_CHAIN_LENGTH, hex(last)))
        assert height >= net.REAL_CHAIN_LENGTH or last is None
        if height < net.TARGET_LOOKBEHIND:
            pre_target3 = net.MAX_TARGET
        else:
            attempts_per_second = get_pool_attempts_per_second(tracker, share_data['previous_share_hash'], net.TARGET_LOOKBEHIND, min_work=True, integer=True)
            pre_target = 2**256//(net.SHARE_PERIOD*attempts_per_second) - 1 if attempts_per_second else 2**256-1
            pre_target2 = math.clip(pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
            pre_target3 = math.clip(pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
        max_bits = pack.FloatingInteger.from_target_upper_bound(pre_target3)
        bits = pack.FloatingInteger.from_target_upper_bound(math.clip(desired_target, (pre_target3//30, pre_target3)))
        
        new_transaction_hashes = []
        new_transaction_size = 0 # including witnesses
        all_transaction_stripped_size = 0 # stripped size
        all_transaction_real_size = 0 # including witnesses, for statistics
        new_transaction_weight = 0
        all_transaction_weight = 0
        transaction_hash_refs = []
        other_transaction_hashes = []
        t1 = time.time()
        past_shares = list(tracker.get_chain(share_data['previous_share_hash'], min(height, 100)))
        tx_hash_to_this = {}
        for i, share in enumerate(past_shares):
            for j, tx_hash in enumerate(share.new_transaction_hashes):
                if tx_hash not in tx_hash_to_this:
                    tx_hash_to_this[tx_hash] = [1+i, j] # share_count, tx_count
        t2 = time.time()
        for tx_hash, fee in desired_other_transaction_hashes_and_fees:
            if known_txs is not None:
                this_stripped_size = coind_data.tx_id_type.packed_size(known_txs[tx_hash])
                this_real_size     = coind_data.tx_type.packed_size(known_txs[tx_hash])
                this_weight        = this_real_size + 3*this_stripped_size
            else: # we're just verifying someone else's share. We'll calculate sizes in should_punish_reason()
                this_stripped_size = 0
                this_real_size = 0
                this_weight = 0

            if all_transaction_stripped_size + this_stripped_size + 80 + cls.gentx_size +  500 > net.BLOCK_MAX_SIZE:
                break
            if all_transaction_weight + this_weight + 4*80 + cls.gentx_weight + 2000 > net.BLOCK_MAX_WEIGHT:
                break

            if tx_hash in tx_hash_to_this:
                this = tx_hash_to_this[tx_hash]
                if known_txs is not None:
                    all_transaction_stripped_size += this_stripped_size
                    all_transaction_real_size += this_real_size
                    all_transaction_weight += this_weight
            else:
                if known_txs is not None:
                    new_transaction_size += this_real_size
                    all_transaction_stripped_size += this_stripped_size
                    all_transaction_real_size += this_real_size
                    new_transaction_weight += this_weight
                    all_transaction_weight += this_weight
                new_transaction_hashes.append(tx_hash)
                this = [0, len(new_transaction_hashes)-1]
            transaction_hash_refs.extend(this)
            other_transaction_hashes.append(tx_hash)

        t3 = time.time()
        if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
            transaction_hash_refs = array.array('H', transaction_hash_refs)
        elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
            transaction_hash_refs = array.array('L', transaction_hash_refs)
        t4 = time.time()

        if all_transaction_stripped_size:
            print("Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
                all_transaction_real_size,
                all_transaction_weight,
                new_transaction_size,
                new_transaction_weight,
                len(other_transaction_hashes),
                len(new_transaction_hashes),
                cls.gentx_size,
                cls.gentx_weight))
            print("Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
                80+all_transaction_stripped_size+cls.gentx_size, 
                80+all_transaction_real_size+cls.gentx_size, 
                3*80+all_transaction_weight+cls.gentx_weight))

        included_transactions = set(other_transaction_hashes)
        removed_fees = [fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash not in included_transactions]
        definite_fees = sum(0 if fee is None else fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash in included_transactions)
        if None not in removed_fees:
            share_data = dict(share_data, subsidy=share_data['subsidy'] - sum(removed_fees))
        else:
            assert base_subsidy is not None
            share_data = dict(share_data, subsidy=base_subsidy + definite_fees)

        #STOPED HERE
        
        weights, total_weight, donation_weight = tracker.get_cumulative_weights(previous_share.share_data['previous_share_hash'] if previous_share is not None else None,
            max(0, min(height, net.REAL_CHAIN_LENGTH) - 1),
            65535*net.SPREAD*coind_data.target_to_average_attempts(block_target),
        )
        assert total_weight == sum(weights.itervalues()) + donation_weight, (total_weight, sum(weights.itervalues()) + donation_weight)
        
        amounts = dict((script, share_data['subsidy']*(199*weight)//(200*total_weight)) for script, weight in weights.iteritems()) # 99.5% goes according to weights prior to this share
        this_script = coind_data.pubkey_hash_to_script2(share_data['pubkey_hash'])
        amounts[this_script] = amounts.get(this_script, 0) + share_data['subsidy']//200 # 0.5% goes to block finder
        amounts[DONATION_SCRIPT] = amounts.get(DONATION_SCRIPT, 0) + share_data['subsidy'] - sum(amounts.itervalues()) # all that's left over is the donation weight and some extra satoshis due to rounding
        
        if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
            raise ValueError()
        
        dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit

        segwit_activated = is_segwit_activated(cls.VERSION, net)
        if segwit_data is None and known_txs is None:
            segwit_activated = False
        if not(segwit_activated or known_txs is None) and any(coind_data.is_segwit_tx(known_txs[h]) for h in other_transaction_hashes):
            raise ValueError('segwit transaction included before activation')
        if segwit_activated and known_txs is not None:
            share_txs = [(known_txs[h], coind_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
            segwit_data = dict(txid_merkle_link=coind_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0),
                               wtxid_merkle_root=coind_data.merkle_hash([0] + [coind_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
        if segwit_activated and segwit_data is not None:
            witness_reserved_value_str = '[P2Pool]'*4
            witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
            witness_commitment_hash = coind_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)

        share_info = dict(
            share_data=share_data,
            far_share_hash=None if last is None and height < 99 else tracker.get_nth_parent_hash(share_data['previous_share_hash'], 99),
            max_bits=max_bits,
            bits=bits,

            timestamp=(math.clip(desired_timestamp, (
                        (previous_share.timestamp + net.SHARE_PERIOD) - (net.SHARE_PERIOD - 1), # = previous_share.timestamp + 1
                        (previous_share.timestamp + net.SHARE_PERIOD) + (net.SHARE_PERIOD - 1),)) if previous_share is not None else desired_timestamp
                      ) if cls.VERSION < 32 else
                      max(desired_timestamp, (previous_share.timestamp + 1)) if previous_share is not None else desired_timestamp,
            new_transaction_hashes=new_transaction_hashes,
            transaction_hash_refs=transaction_hash_refs,
            absheight=((previous_share.absheight if previous_share is not None else 0) + 1) % 2**32,
            abswork=((previous_share.abswork if previous_share is not None else 0) + coind_data.target_to_average_attempts(bits.target)) % 2**128,
        )

        if previous_share != None and desired_timestamp > previous_share.timestamp + 180:
            print ("Warning: Previous share's timestamp is %i seconds old." % int(desired_timestamp - previous_share.timestamp))
            print ("Make sure your system clock is accurate, and ensure that you're connected to decent peers.")
            print ("If your clock is more than 300 seconds behind, it can result in orphaned shares.")
            print ("(It's also possible that this share is just taking a long time to mine.)")
        if previous_share != None and previous_share.timestamp > int(time.time()) + 3:
            print ("WARNING! Previous share's timestamp is %i seconds in the future. This is not normal." % \
                   int(previous_share.timestamp - (int(time.time()))))
            print ("Make sure your system clock is accurate. Errors beyond 300 sec result in orphaned shares.")

        if segwit_activated:
            share_info['segwit_data'] = segwit_data
        
        gentx = dict(
            version=1,
            tx_ins=[dict(
                previous_output=None,
                sequence=None,
                script=share_data['coinbase'],
            )],
            tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed' + pack.IntType(256).pack(witness_commitment_hash))] if segwit_activated else []) +
                [dict(value=amounts[script], script=script) for script in dests if amounts[script] or script == DONATION_SCRIPT] +
                [dict(value=0, script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce))],
            lock_time=0,
        )
        if segwit_activated:
            gentx['marker'] = 0
            gentx['flag'] = 1
            gentx['witness'] = [[witness_reserved_value_str]]
        
        def get_share(header, last_txout_nonce=last_txout_nonce):
            min_header = dict(header); del min_header['merkle_root']
            share = cls(net, None, dict(
                min_header=min_header,
                share_info=share_info,
                ref_merkle_link=dict(branch=[], index=0),
                last_txout_nonce=last_txout_nonce,
                hash_link=data.prefix_to_hash_link(coind_data.tx_id_type.pack(gentx)[:-32-8-4], cls.gentx_before_refhash),
                merkle_link=coind_data.calculate_merkle_link([None] + other_transaction_hashes, 0),
            ))
            assert share.header == header # checks merkle_root
            return share
        t5 = time.time()
        if True: print ("%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
            (t5-t0)*1000.,
            (t1-t0)*1000.,
            (t2-t1)*1000.,
            (t3-t2)*1000.,
            (t4-t3)*1000.,
            (t5-t4)*1000.))
        return share_info, gentx, other_transaction_hashes, get_share

    @classmethod
    def generate_transaction2(cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None):
        t0 = time.time()
        previous_share = tracker.items[share_data['previous_share_hash']] if share_data['previous_share_hash'] is not None else None
        
        height, last = tracker.get_height_and_last(share_data['previous_share_hash'])
        print('{0}, {1}, {2}'.format(height, net.REAL_CHAIN_LENGTH, hex(last)))
        assert height >= net.REAL_CHAIN_LENGTH or last is None
        if height < net.TARGET_LOOKBEHIND:
            pre_target3 = net.MAX_TARGET
        else:
            attempts_per_second = get_pool_attempts_per_second(tracker, share_data['previous_share_hash'], net.TARGET_LOOKBEHIND, min_work=True, integer=True)
            pre_target = 2**256//(net.SHARE_PERIOD*attempts_per_second) - 1 if attempts_per_second else 2**256-1
            pre_target2 = math.clip(pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
            pre_target3 = math.clip(pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
        max_bits = pack.FloatingInteger.from_target_upper_bound(pre_target3)
        bits = pack.FloatingInteger.from_target_upper_bound(math.clip(desired_target, (pre_target3//30, pre_target3)))
        
        new_transaction_hashes = []
        new_transaction_size = 0 # including witnesses
        all_transaction_stripped_size = 0 # stripped size
        all_transaction_real_size = 0 # including witnesses, for statistics
        new_transaction_weight = 0
        all_transaction_weight = 0
        transaction_hash_refs = []
        other_transaction_hashes = []
        t1 = time.time()
        past_shares = list(tracker.get_chain(share_data['previous_share_hash'], min(height, 100)))
        tx_hash_to_this = {}
        for i, share in enumerate(past_shares):
            for j, tx_hash in enumerate(share.new_transaction_hashes):
                if tx_hash not in tx_hash_to_this:
                    tx_hash_to_this[tx_hash] = [1+i, j] # share_count, tx_count
        t2 = time.time()
        for tx_hash, fee in desired_other_transaction_hashes_and_fees:
            if known_txs is not None:
                this_stripped_size = coind_data.tx_id_type.packed_size(known_txs[tx_hash])
                this_real_size     = coind_data.tx_type.packed_size(known_txs[tx_hash])
                this_weight        = this_real_size + 3*this_stripped_size
            else: # we're just verifying someone else's share. We'll calculate sizes in should_punish_reason()
                this_stripped_size = 0
                this_real_size = 0
                this_weight = 0

            if all_transaction_stripped_size + this_stripped_size + 80 + cls.gentx_size +  500 > net.BLOCK_MAX_SIZE:
                break
            if all_transaction_weight + this_weight + 4*80 + cls.gentx_weight + 2000 > net.BLOCK_MAX_WEIGHT:
                break

            if tx_hash in tx_hash_to_this:
                this = tx_hash_to_this[tx_hash]
                if known_txs is not None:
                    all_transaction_stripped_size += this_stripped_size
                    all_transaction_real_size += this_real_size
                    all_transaction_weight += this_weight
            else:
                if known_txs is not None:
                    new_transaction_size += this_real_size
                    all_transaction_stripped_size += this_stripped_size
                    all_transaction_real_size += this_real_size
                    new_transaction_weight += this_weight
                    all_transaction_weight += this_weight
                new_transaction_hashes.append(tx_hash)
                this = [0, len(new_transaction_hashes)-1]
            transaction_hash_refs.extend(this)
            other_transaction_hashes.append(tx_hash)

        t3 = time.time()
        if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
            transaction_hash_refs = array.array('H', transaction_hash_refs)
        elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
            transaction_hash_refs = array.array('L', transaction_hash_refs)
        t4 = time.time()

        if all_transaction_stripped_size:
            print("Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
                all_transaction_real_size,
                all_transaction_weight,
                new_transaction_size,
                new_transaction_weight,
                len(other_transaction_hashes),
                len(new_transaction_hashes),
                cls.gentx_size,
                cls.gentx_weight))
            print("Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
                80+all_transaction_stripped_size+cls.gentx_size, 
                80+all_transaction_real_size+cls.gentx_size, 
                3*80+all_transaction_weight+cls.gentx_weight))

        included_transactions = set(other_transaction_hashes)
        removed_fees = [fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash not in included_transactions]
        definite_fees = sum(0 if fee is None else fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash in included_transactions)
        if None not in removed_fees:
            share_data = dict(share_data, subsidy=share_data['subsidy'] - sum(removed_fees))
        else:
            assert base_subsidy is not None
            share_data = dict(share_data, subsidy=base_subsidy + definite_fees)

        #STOPED HERE
        print('block_target: {0}'.format(hex(block_target)))
        print('block_target_attempts: {0}'.format(hex(coind_data.target_to_average_attempts(block_target))))
        print('For get_cumulative_weights: {0}, {1}, {2}'.format(hex(previous_share.share_data['previous_share_hash'] if previous_share is not None else None),
            max(0, min(height, net.REAL_CHAIN_LENGTH) - 1),
            hex(65535*net.SPREAD*coind_data.target_to_average_attempts(block_target))))
        001dffe20000000000000000000000000000000000000000000000000000000000000000
        1dffe20000000000000000000000000000000000000000000000000000000
        weights, total_weight, donation_weight = tracker.get_cumulative_weights(previous_share.share_data['previous_share_hash'] if previous_share is not None else None,
            max(0, min(height, net.REAL_CHAIN_LENGTH) - 1),
            65535*net.SPREAD*coind_data.target_to_average_attempts(block_target),
        )
        assert total_weight == sum(weights.itervalues()) + donation_weight, (total_weight, sum(weights.itervalues()) + donation_weight)
        
        amounts = dict((script, share_data['subsidy']*(199*weight)//(200*total_weight)) for script, weight in weights.iteritems()) # 99.5% goes according to weights prior to this share
        this_script = coind_data.pubkey_hash_to_script2(share_data['pubkey_hash'])
        amounts[this_script] = amounts.get(this_script, 0) + share_data['subsidy']//200 # 0.5% goes to block finder
        amounts[DONATION_SCRIPT] = amounts.get(DONATION_SCRIPT, 0) + share_data['subsidy'] - sum(amounts.itervalues()) # all that's left over is the donation weight and some extra satoshis due to rounding
        
        if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
            raise ValueError()
        
        dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit

        segwit_activated = is_segwit_activated(cls.VERSION, net)
        if segwit_data is None and known_txs is None:
            segwit_activated = False
        if not(segwit_activated or known_txs is None) and any(coind_data.is_segwit_tx(known_txs[h]) for h in other_transaction_hashes):
            raise ValueError('segwit transaction included before activation')
        if segwit_activated and known_txs is not None:
            share_txs = [(known_txs[h], coind_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
            segwit_data = dict(txid_merkle_link=coind_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0),
                               wtxid_merkle_root=coind_data.merkle_hash([0] + [coind_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
        if segwit_activated and segwit_data is not None:
            witness_reserved_value_str = '[P2Pool]'*4
            witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
            witness_commitment_hash = coind_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)

        share_info = dict(
            share_data=share_data,
            far_share_hash=None if last is None and height < 99 else tracker.get_nth_parent_hash(share_data['previous_share_hash'], 99),
            max_bits=max_bits,
            bits=bits,

            timestamp=(math.clip(desired_timestamp, (
                        (previous_share.timestamp + net.SHARE_PERIOD) - (net.SHARE_PERIOD - 1), # = previous_share.timestamp + 1
                        (previous_share.timestamp + net.SHARE_PERIOD) + (net.SHARE_PERIOD - 1),)) if previous_share is not None else desired_timestamp
                      ) if cls.VERSION < 32 else
                      max(desired_timestamp, (previous_share.timestamp + 1)) if previous_share is not None else desired_timestamp,
            new_transaction_hashes=new_transaction_hashes,
            transaction_hash_refs=transaction_hash_refs,
            absheight=((previous_share.absheight if previous_share is not None else 0) + 1) % 2**32,
            abswork=((previous_share.abswork if previous_share is not None else 0) + coind_data.target_to_average_attempts(bits.target)) % 2**128,
        )

        if previous_share != None and desired_timestamp > previous_share.timestamp + 180:
            print ("Warning: Previous share's timestamp is %i seconds old." % int(desired_timestamp - previous_share.timestamp))
            print ("Make sure your system clock is accurate, and ensure that you're connected to decent peers.")
            print ("If your clock is more than 300 seconds behind, it can result in orphaned shares.")
            print ("(It's also possible that this share is just taking a long time to mine.)")
        if previous_share != None and previous_share.timestamp > int(time.time()) + 3:
            print ("WARNING! Previous share's timestamp is %i seconds in the future. This is not normal." % \
                   int(previous_share.timestamp - (int(time.time()))))
            print ("Make sure your system clock is accurate. Errors beyond 300 sec result in orphaned shares.")

        if segwit_activated:
            share_info['segwit_data'] = segwit_data
        
        gentx = dict(
            version=1,
            tx_ins=[dict(
                previous_output=None,
                sequence=None,
                script=share_data['coinbase'],
            )],
            tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed' + pack.IntType(256).pack(witness_commitment_hash))] if segwit_activated else []) +
                [dict(value=amounts[script], script=script) for script in dests if amounts[script] or script == DONATION_SCRIPT] +
                [dict(value=0, script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce))],
            lock_time=0,
        )
        if segwit_activated:
            gentx['marker'] = 0
            gentx['flag'] = 1
            gentx['witness'] = [[witness_reserved_value_str]]
        
        def get_share(header, last_txout_nonce=last_txout_nonce):
            min_header = dict(header); del min_header['merkle_root']
            share = cls(net, None, dict(
                min_header=min_header,
                share_info=share_info,
                ref_merkle_link=dict(branch=[], index=0),
                last_txout_nonce=last_txout_nonce,
                hash_link=data.prefix_to_hash_link(coind_data.tx_id_type.pack(gentx)[:-32-8-4], cls.gentx_before_refhash),
                merkle_link=coind_data.calculate_merkle_link([None] + other_transaction_hashes, 0),
            ))
            assert share.header == header # checks merkle_root
            return share
        t5 = time.time()
        if True: print ("%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
            (t5-t0)*1000.,
            (t1-t0)*1000.,
            (t2-t1)*1000.,
            (t3-t2)*1000.,
            (t4-t3)*1000.,
            (t5-t4)*1000.))
        return share_info, gentx, other_transaction_hashes, get_share
    
    @classmethod
    def get_ref_hash(cls, net, share_info, ref_merkle_link):
        return pack.IntType(256).pack(coind_data.check_merkle_link(coind_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(
            identifier=net.IDENTIFIER,
            share_info=share_info,
        ))), ref_merkle_link))
    
    __slots__ = 'net peer_addr contents min_header share_info hash_link merkle_link hash share_data max_target target timestamp previous_hash new_script desired_version gentx_hash header pow_hash header_hash new_transaction_hashes time_seen absheight abswork'.split(' ')
    
    def __init__(self, net, peer_addr, contents):
        dynamic_types = self.get_dynamic_types(net)
        self.share_info_type = dynamic_types['share_info_type']
        self.share_type = dynamic_types['share_type']
        self.ref_type = dynamic_types['ref_type']

        self.net = net
        self.peer_addr = peer_addr
        self.contents = contents
        
        self.min_header = contents['min_header']
        self.share_info = contents['share_info']
        self.hash_link = contents['hash_link']
        self.merkle_link = contents['merkle_link']

        # save some memory if we can
        txrefs = self.share_info['transaction_hash_refs']
        if txrefs and max(txrefs) < 2**16:
            self.share_info['transaction_hash_refs'] = array.array('H', txrefs)
        elif txrefs and max(txrefs) < 2**32: # in case we see blocks with more than 65536 tx in the future
            self.share_info['transaction_hash_refs'] = array.array('L', txrefs)
        
        segwit_activated = is_segwit_activated(self.VERSION, net)
        
        if not (2 <= len(self.share_info['share_data']['coinbase']) <= 100):
            raise ValueError('''bad coinbase size! %i bytes''' % (len(self.share_info['share_data']['coinbase']),))
        
        if len(self.merkle_link['branch']) > 16 or (segwit_activated and len(self.share_info['segwit_data']['txid_merkle_link']['branch']) > 16):
            raise ValueError('merkle branch too long!')
        
        assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])
        
        self.share_data = self.share_info['share_data']
        self.max_target = self.share_info['max_bits'].target
        self.target = self.share_info['bits'].target
        self.timestamp = self.share_info['timestamp']
        self.previous_hash = self.share_data['previous_share_hash']
        self.new_script = coind_data.pubkey_hash_to_script2(self.share_data['pubkey_hash'])
        self.desired_version = self.share_data['desired_version']
        self.absheight = self.share_info['absheight']
        self.abswork = self.share_info['abswork']
        # REM
        # if net.NAME == 'bitcoin' and self.absheight > 3927800 and self.desired_version == 16:
        #     raise ValueError("This is not a hardfork-supporting share!")
        
        n = set()
        for share_count, tx_count in self.iter_transaction_hash_refs():
            assert share_count < 110
            if share_count == 0:
                n.add(tx_count)
        assert n == set(range(len(self.share_info['new_transaction_hashes'])))
        
        self.gentx_hash = data.check_hash_link(
            self.hash_link,
            self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
            self.gentx_before_refhash,
        )
        merkle_root = coind_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
        self.header = dict(self.min_header, merkle_root=merkle_root)
        self.pow_hash = net.PARENT.POW_FUNC(coind_data.block_header_type.pack(self.header))
        self.hash = self.header_hash = coind_data.hash256(coind_data.block_header_type.pack(self.header))
        
        if self.target > net.MAX_TARGET:
            print('[WARNING] share target invalid')
        
        if self.pow_hash > self.target:
            print('[WARNING] share PoW invalid')
        
        self.new_transaction_hashes = self.share_info['new_transaction_hashes']
        
        # XXX eww
        self.time_seen = time.time()
    
    def __repr__(self):
        return 'Share' + repr((self.net, self.peer_addr, self.contents))
    
    def as_share(self):
        return dict(type=self.VERSION, contents=self.share_type.pack(self.contents))
    
    def iter_transaction_hash_refs(self):
        return zip(self.share_info['transaction_hash_refs'][::2], self.share_info['transaction_hash_refs'][1::2])
    
    def check(self, tracker, other_txs=None):
        # from p2pool import p2p
        if self.timestamp > int(time.time()) + 600:
            raise ValueError("Share timestamp is %i seconds in the future! Check your system clock." % \
                self.timestamp - int(time.time()))
        counts = None
        if self.share_data['previous_share_hash'] is not None:
            previous_share = tracker.items[self.share_data['previous_share_hash']]
            if tracker.get_height(self.share_data['previous_share_hash']) >= self.net.CHAIN_LENGTH:
                counts = get_desired_version_counts(tracker, tracker.get_nth_parent_hash(previous_share.hash, self.net.CHAIN_LENGTH*9//10), self.net.CHAIN_LENGTH//10)
                if type(self) is type(previous_share):
                    pass
                elif type(self) is type(previous_share).SUCCESSOR:
                    # switch only valid if 60% of hashes in [self.net.CHAIN_LENGTH*9//10, self.net.CHAIN_LENGTH] for new version
                    if counts.get(self.VERSION, 0) < sum(counts.itervalues())*60//100:
                        print('switch without enough hash power upgraded')
                else:
                    print('''%s can't follow %s''' % (type(self).__name__, type(previous_share).__name__))
            elif type(self) is type(previous_share).SUCCESSOR:
                print('switch without enough history')
        
        other_tx_hashes = [tracker.items[tracker.get_nth_parent_hash(self.hash, share_count)].share_info['new_transaction_hashes'][tx_count] for share_count, tx_count in self.iter_transaction_hash_refs()]
        if other_txs is not None and not isinstance(other_txs, dict): other_txs = dict((coind_data.hash256(coind_data.tx_type.pack(tx)), tx) for tx in other_txs)
        
        share_info, gentx, other_tx_hashes2, get_share = self.generate_transaction(tracker, self.share_info['share_data'], self.header['bits'].target, self.share_info['timestamp'], self.share_info['bits'].target, self.contents['ref_merkle_link'], [(h, None) for h in other_tx_hashes], self.net,
            known_txs=other_txs, last_txout_nonce=self.contents['last_txout_nonce'], segwit_data=self.share_info.get('segwit_data', None))
        

        assert other_tx_hashes2 == other_tx_hashes
        if share_info != self.share_info:
            raise ValueError('share_info invalid')
        if coind_data.get_txid(gentx) != self.gentx_hash:
            raise ValueError('''gentx doesn't match hash_link''')
        if coind_data.calculate_merkle_link([None] + other_tx_hashes, 0) != self.merkle_link: # the other hash commitments are checked in the share_info assertion
            raise ValueError('merkle_link and other_tx_hashes do not match')
        
        update_min_protocol_version(counts, self)

        self.gentx_size = len(coind_data.tx_id_type.pack(gentx))
        self.gentx_weight = len(coind_data.tx_type.pack(gentx)) + 3*self.gentx_size

        type(self).gentx_size   = self.gentx_size # saving this share's gentx size as a class variable is an ugly hack, and you're welcome to hate me for doing it. But it works.
        type(self).gentx_weight = self.gentx_weight

        return gentx # only used by as_block
    
    def get_other_tx_hashes(self, tracker):
        parents_needed = max(share_count for share_count, tx_count in self.iter_transaction_hash_refs()) if self.share_info['transaction_hash_refs'] else 0
        parents = tracker.get_height(self.hash) - 1
        if parents < parents_needed:
            return None
        last_shares = list(tracker.get_chain(self.hash, parents_needed + 1))
        return [last_shares[share_count].share_info['new_transaction_hashes'][tx_count] for share_count, tx_count in self.iter_transaction_hash_refs()]
    
    def _get_other_txs(self, tracker, known_txs):
        other_tx_hashes = self.get_other_tx_hashes(tracker)
        if other_tx_hashes is None:
            return None # not all parents present
        
        if not all(tx_hash in known_txs for tx_hash in other_tx_hashes):
            return None # not all txs present
        
        return [known_txs[tx_hash] for tx_hash in other_tx_hashes]
    
    def should_punish_reason(self, previous_block, bits, tracker, known_txs):
        if self.pow_hash <= self.header['bits'].target:
            return -1, 'block solution'
        
        other_txs = self._get_other_txs(tracker, known_txs)
        if other_txs is None:
            pass
        else:
            all_txs_size = sum(coind_data.tx_type.packed_size(tx) for tx in other_txs)
            stripped_txs_size = sum(coind_data.tx_id_type.packed_size(tx) for tx in other_txs)
            # if p2pool.DEBUG:
            if True:
                print ("stripped_txs_size = %i, all_txs_size = %i, weight = %i" % (stripped_txs_size, all_txs_size, all_txs_size + 3 * stripped_txs_size))
                print ("Block size = %i, block weight = %i" %(stripped_txs_size + 80 + self.gentx_size , all_txs_size + 3 * stripped_txs_size + 4*80 + self.gentx_weight))
            if all_txs_size + 3 * stripped_txs_size + 4*80 + self.gentx_weight > tracker.net.BLOCK_MAX_WEIGHT:
                return True, 'txs over block weight limit'
            if stripped_txs_size + 80 + self.gentx_size > tracker.net.BLOCK_MAX_SIZE:
                return True, 'txs over block size limit'
        
        return False, None
    
    def as_block(self, tracker, known_txs):
        other_txs = self._get_other_txs(tracker, known_txs)
        if other_txs is None:
            return None # not all txs present
        return dict(header=self.header, txs=[self.check(tracker, other_txs)] + other_txs)

class NewShare(BaseShare):
    VERSION = 33
    VOTING_VERSION = 33
    SUCCESSOR = None

class PreSegwitShare(BaseShare):
    VERSION = 32
    VOTING_VERSION = 32
    SUCCESSOR = NewShare

class Share(BaseShare):
    VERSION = 17
    VOTING_VERSION = 17
    SUCCESSOR = NewShare


share_versions = {s.VERSION:s for s in [NewShare, PreSegwitShare, Share]}

def get_pool_attempts_per_second(tracker, previous_share_hash, dist, min_work=False, integer=False):
    assert dist >= 2
    near = tracker.items[previous_share_hash]
    far = tracker.items[tracker.get_nth_parent_hash(previous_share_hash, dist - 1)]
    attempts = tracker.get_delta(near.hash, far.hash).work if not min_work else tracker.get_delta(near.hash, far.hash).min_work
    time = near.timestamp - far.timestamp
    if time <= 0:
        time = 1
    if integer:
        return attempts//time
    return attempts/time

def get_desired_version_counts(tracker, best_share_hash, dist):
    res = {}
    for share in tracker.get_chain(best_share_hash, dist):
        res[share.desired_version] = res.get(share.desired_version, 0) + coind_data.target_to_average_attempts(share.target)
    return res

def update_min_protocol_version(counts, share):
    minpver = getattr(share.net, 'MINIMUM_PROTOCOL_VERSION', 1400)
    newminpver = getattr(share.net, 'NEW_MINIMUM_PROTOCOL_VERSION', minpver)
    if (counts is not None) and (type(share) is NewShare) and (minpver < newminpver):
            if counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100:
                share.net.MINIMUM_PROTOCOL_VERSION = newminpver # Reject peers running obsolete nodes
                print('Setting MINIMUM_PROTOCOL_VERSION = %d' % (newminpver))