#include<string>

class BaseShare {
    // Share version
    int VERSION = 0;
    // desired version
    int VOTING_VERSION = 0;
    // None/SegwitMiningShare
    int* SUCCESSOR = nullptr; //None

    newType1 small_block_header_type = packFunc(); /*pack.ComposedType([
        ('version', pack.VarIntType()),
        ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
        ('timestamp', pack.IntType(32)),
        ('bits', bitcoin_data.FloatingIntegerType()),
        ('nonce', pack.IntType(32)),
        ]);*/

    
    int* share_info_type = nullptr; //None

    int* share_type = nullptr; //None

    int* ref_type = nullptr; //None

    // DONATION_SCRIPT is packed here, which is used in def generate_transaction [data.py, line 387]
    newType1 gentx_before_refhash = newFunc1();/*pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + \
        pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) +
                               pack.IntType(64).pack(0))[:3]*/

    //conservative estimate, will be overwritten during execution
    float gentx_size = 50000;
    float gentx_weight = 200000;
    newType2* cached_types = nullptr;//None

    //@classmethod
    public:
    newType3 get_dynamic_types(cls, net) {
    /* def get_dynamic_types(cls, net):
        if not cls.cached_types == None:
            return cls.cached_types
        t = dict(share_info_type=None, share_type=None, ref_type=None)
        segwit_data = ('segwit_data', pack.PossiblyNoneType(dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=2**256-1), pack.ComposedType([
            ('txid_merkle_link', pack.ComposedType([
                ('branch', pack.ListType(pack.IntType(256))),
                ('index', pack.IntType(0)),  # it will always be 0
            ])),
            ('wtxid_merkle_root', pack.IntType(256))
        ])))
        t['share_info_type'] = pack.ComposedType([
            ('share_data', pack.ComposedType([
                ('previous_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
                ('coinbase', pack.VarStrType()),
                ('nonce', pack.IntType(32)),
            ] + ([('address', pack.VarStrType())]
                 if cls.VERSION >= 34
                 else [('pubkey_hash', pack.IntType(160))]) + [
                ('subsidy', pack.IntType(64)),
                ('donation', pack.IntType(16)),
                ('stale_info', pack.EnumType(pack.IntType(8), dict(
                    (k, {0: None, 253: 'orphan', 254: 'doa'}.get(k, 'unk%i' % (k,))) for k in xrange(256)))),
                ('desired_version', pack.VarIntType()),
            ]))] + ([segwit_data] if is_segwit_activated(cls.VERSION, net) else []) + ([
                ('new_transaction_hashes', pack.ListType(pack.IntType(256))),
                # pairs of share_count, tx_count
                ('transaction_hash_refs', pack.ListType(pack.VarIntType(), 2)),
            ] if cls.VERSION < 34 else []) + [
            ('far_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
            ('max_bits', bitcoin_data.FloatingIntegerType()),
            ('bits', bitcoin_data.FloatingIntegerType()),
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
            ('hash_link', hash_link_type),
            ('merkle_link', pack.ComposedType([
                ('branch', pack.ListType(pack.IntType(256))),
                ('index', pack.IntType(0)),  # it will always be 0
            ])),
        ])
        t['ref_type'] = pack.ComposedType([
            ('identifier', pack.FixedStrType(64//8)),
            ('share_info', t['share_info_type']),
        ])
        cls.cached_types = t
        return t*/
    }


    //@classmethod
    public:
    newType3 generate_transaction(cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None){
    /*
    def generate_transaction(cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None):
        t0 = time.time()
        previous_share = tracker.items[share_data['previous_share_hash']
                                       ] if share_data['previous_share_hash'] is not None else None

        height, last = tracker.get_height_and_last(
            share_data['previous_share_hash'])
        assert height >= net.REAL_CHAIN_LENGTH or last is None
        if height < net.TARGET_LOOKBEHIND:
            pre_target3 = net.MAX_TARGET
        else:
            attempts_per_second = get_pool_attempts_per_second(
                tracker, share_data['previous_share_hash'], net.TARGET_LOOKBEHIND, min_work=True, integer=True)
            pre_target = 2**256//(net.SHARE_PERIOD*attempts_per_second) - \
                1 if attempts_per_second else 2**256-1
            pre_target2 = math.clip(
                pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
            pre_target3 = math.clip(
                pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
        max_bits = bitcoin_data.FloatingInteger.from_target_upper_bound(
            pre_target3)
        bits = bitcoin_data.FloatingInteger.from_target_upper_bound(
            math.clip(desired_target, (pre_target3//30, pre_target3)))

        new_transaction_hashes = []
        new_transaction_size = 0  # including witnesses
        all_transaction_stripped_size = 0  # stripped size
        all_transaction_real_size = 0  # including witnesses, for statistics
        new_transaction_weight = 0
        all_transaction_weight = 0
        transaction_hash_refs = []
        other_transaction_hashes = []
        t1 = time.time()
        tx_hash_to_this = {}
        if cls.VERSION < 34:
            past_shares = list(tracker.get_chain(
                share_data['previous_share_hash'], min(height, 100)))
            for i, share in enumerate(past_shares):
                for j, tx_hash in enumerate(share.new_transaction_hashes):
                    if tx_hash not in tx_hash_to_this:
                        tx_hash_to_this[tx_hash] = [
                            1+i, j]  # share_count, tx_count

        t2 = time.time()
        for tx_hash, fee in desired_other_transaction_hashes_and_fees:
            if known_txs is not None:
                this_stripped_size = bitcoin_data.get_stripped_size(
                    known_txs[tx_hash])
                this_real_size = bitcoin_data.get_size(known_txs[tx_hash])
                this_weight = this_real_size + 3*this_stripped_size
            else:  # we're just verifying someone else's share. We'll calculate sizes in should_punish_reason()
                this_stripped_size = 0
                this_real_size = 0
                this_weight = 0

            if all_transaction_stripped_size + this_stripped_size + 80 + cls.gentx_size + 500 > net.BLOCK_MAX_SIZE:
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
        # in case we see blocks with more than 65536 tx
        elif transaction_hash_refs and max(transaction_hash_refs) < 2**32:
            transaction_hash_refs = array.array('L', transaction_hash_refs)
        t4 = time.time()

        if all_transaction_stripped_size and p2pool.DEBUG:
            print "Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
                all_transaction_real_size,
                all_transaction_weight,
                new_transaction_size,
                new_transaction_weight,
                len(other_transaction_hashes),
                len(new_transaction_hashes),
                cls.gentx_size,
                cls.gentx_weight)
            print "Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
                80+all_transaction_stripped_size+cls.gentx_size,
                80+all_transaction_real_size+cls.gentx_size,
                3*80+all_transaction_weight+cls.gentx_weight)

        included_transactions = set(other_transaction_hashes)
        removed_fees = [
            fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash not in included_transactions]
        definite_fees = sum(0 if fee is None else fee for tx_hash,
                            fee in desired_other_transaction_hashes_and_fees if tx_hash in included_transactions)
        if None not in removed_fees:
            share_data = dict(
                share_data, subsidy=share_data['subsidy'] - sum(removed_fees))
        else:
            assert base_subsidy is not None
            share_data = dict(share_data, subsidy=base_subsidy + definite_fees)

        weights, total_weight, donation_weight = tracker.get_cumulative_weights(previous_share.share_data['previous_share_hash'] if previous_share is not None else None,
                                                                                max(0, min(
                                                                                    height, net.REAL_CHAIN_LENGTH) - 1),
                                                                                65535*net.SPREAD *
                                                                                bitcoin_data.target_to_average_attempts(
                                                                                    block_target),
                                                                                )
        assert total_weight == sum(weights.itervalues(
        )) + donation_weight, (total_weight, sum(weights.itervalues()) + donation_weight)

        # 99.5% goes according to weights prior to this share
        amounts = dict((script, share_data['subsidy']*(199*weight)//(
            200*total_weight)) for script, weight in weights.iteritems())
        if 'address' not in share_data:
            this_address = bitcoin_data.pubkey_hash_to_address(
                share_data['pubkey_hash'], net.PARENT.ADDRESS_VERSION,
                -1, net.PARENT)
        else:
            this_address = share_data['address']
        donation_address = donation_script_to_address(net)
        # 0.5% goes to block finder
        amounts[this_address] = amounts.get(this_address, 0) \
            + share_data['subsidy']//200
        # all that's left over is the donation weight and some extra
        # satoshis due to rounding
        amounts[donation_address] = amounts.get(donation_address, 0) \
            + share_data['subsidy'] \
            - sum(amounts.itervalues())
        if cls.VERSION < 34 and 'pubkey_hash' not in share_data:
            share_data['pubkey_hash'], _, _ = bitcoin_data.address_to_pubkey_hash(
                this_address, net.PARENT)
            del(share_data['address'])

        if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
            raise ValueError()

        # block length limit, unlikely to ever be hit
        dests = sorted(amounts.iterkeys(), key=lambda address: (
            address == donation_address, amounts[address], address))[-4000:]
        if len(dests) >= 200:
            print "found %i payment dests. Antminer S9s may crash when this is close to 226." % len(
                dests)

        segwit_activated = is_segwit_activated(cls.VERSION, net)
        if segwit_data is None and known_txs is None:
            segwit_activated = False
        if not(segwit_activated or known_txs is None) and any(bitcoin_data.is_segwit_tx(known_txs[h]) for h in other_transaction_hashes):
            raise ValueError('segwit transaction included before activation')
        if segwit_activated and known_txs is not None:
            share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h)
                         for h in other_transaction_hashes]
            segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link(
                [None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
        if segwit_activated and segwit_data is not None:
            witness_reserved_value_str = '[P2Pool]'*4
            witness_reserved_value = pack.IntType(
                256).unpack(witness_reserved_value_str)
            witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(
                segwit_data['wtxid_merkle_root'], witness_reserved_value)

        share_info = dict(
            share_data=share_data,
            far_share_hash=None if last is None and height < 99 else tracker.get_nth_parent_hash(
                share_data['previous_share_hash'], 99),
            max_bits=max_bits,
            bits=bits,

            timestamp=(math.clip(desired_timestamp, (
                (previous_share.timestamp + net.SHARE_PERIOD) -
                (net.SHARE_PERIOD - 1),  # = previous_share.timestamp + 1
                (previous_share.timestamp + net.SHARE_PERIOD) + (net.SHARE_PERIOD - 1),)) if previous_share is not None else desired_timestamp
            ) if cls.VERSION < 32 else
            max(desired_timestamp, (previous_share.timestamp + 1)
                ) if previous_share is not None else desired_timestamp,
            absheight=(
                (previous_share.absheight if previous_share is not None else 0) + 1) % 2**32,
            abswork=((previous_share.abswork if previous_share is not None else 0) + \
                     bitcoin_data.target_to_average_attempts(bits.target)) % 2**128,
        )
        if cls.VERSION < 34:
            share_info['new_transaction_hashes'] = new_transaction_hashes
            share_info['transaction_hash_refs'] = transaction_hash_refs

        if previous_share != None and desired_timestamp > previous_share.timestamp + 180:
            print "Warning: Previous share's timestamp is %i seconds old." % int(
                desired_timestamp - previous_share.timestamp)
            print "Make sure your system clock is accurate, and ensure that you're connected to decent peers."
            print "If your clock is more than 300 seconds behind, it can result in orphaned shares."
            print "(It's also possible that this share is just taking a long time to mine.)"
        if previous_share != None and previous_share.timestamp > int(time.time()) + 3:
            print "WARNING! Previous share's timestamp is %i seconds in the future. This is not normal." % \
                int(previous_share.timestamp - (int(time.time())))
            print "Make sure your system clock is accurate. Errors beyond 300 sec result in orphaned shares."

        if segwit_activated:
            share_info['segwit_data'] = segwit_data

        payouts = [dict(value=amounts[addr],
                        script=bitcoin_data.address_to_script2(
                            addr, net.PARENT)
                        ) for addr in dests if amounts[addr] and addr != donation_address]
        payouts.append({'script': DONATION_SCRIPT,
                        'value': amounts[donation_address]})

        gentx = dict(
            version=1,
            tx_ins=[dict(
                previous_output=None,
                sequence=None,
                script=share_data['coinbase'],
            )],
            tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed'
                                           + pack.IntType(256).pack(
                                               witness_commitment_hash))]
                     if segwit_activated else [])
            + payouts
            + [dict(value=0, script='\x6a\x28' + cls.get_ref_hash(
                net, share_info, ref_merkle_link)
                + pack.IntType(64).pack(last_txout_nonce))],
            lock_time=0,
        )
        if segwit_activated:
            gentx['marker'] = 0
            gentx['flag'] = 1
            gentx['witness'] = [[witness_reserved_value_str]]

        def get_share(header, last_txout_nonce=last_txout_nonce):
            min_header = dict(header)
            del min_header['merkle_root']
            share = cls(net, None, dict(
                min_header=min_header,
                share_info=share_info,
                ref_merkle_link=dict(branch=[], index=0),
                last_txout_nonce=last_txout_nonce,
                hash_link=prefix_to_hash_link(bitcoin_data.tx_id_type.pack(gentx)[
                                              :-32-8-4], cls.gentx_before_refhash),
                merkle_link=bitcoin_data.calculate_merkle_link(
                    [None] + other_transaction_hashes, 0),
            ))
            assert share.header == header  # checks merkle_root
            return share
        t5 = time.time()
        if p2pool.BENCH:
            print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
                (t5-t0)*1000.,
                (t1-t0)*1000.,
                (t2-t1)*1000.,
                (t3-t2)*1000.,
                (t4-t3)*1000.,
                (t5-t4)*1000.)
        return share_info, gentx, other_transaction_hashes, get_share*/

    }


    //@classmethod
    public:
    newType4 get_ref_hash(cls, net, share_info, ref_merkle_link){
    /*
    def get_ref_hash(cls, net, share_info, ref_merkle_link):
        return pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(
            identifier=net.IDENTIFIER,
            share_info=share_info,
        ))), ref_merkle_link))*/
    }


    string __slots__ = ""; //'net peer_addr contents min_header share_info hash_link merkle_link hash share_data max_target target timestamp previous_hash new_script desired_version gentx_hash header pow_hash header_hash new_transaction_hashes time_seen absheight abswork'.split(' ')

    public:
    void baseShare(self, net, peer_addr, contents){//conctruct
        /*def __init__(self, net, peer_addr, contents):
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
        self.naughty = 0

        # save some memory if we can
        if self.VERSION < 34:
            txrefs = self.share_info['transaction_hash_refs']
            if txrefs and max(txrefs) < 2**16:
                self.share_info['transaction_hash_refs'] = array.array(
                    'H', txrefs)
            # in case we see blocks with more than 65536 tx in the future
            elif txrefs and max(txrefs) < 2**32:
                self.share_info['transaction_hash_refs'] = array.array(
                    'L', txrefs)

        segwit_activated = is_segwit_activated(self.VERSION, net)

        if not (2 <= len(self.share_info['share_data']['coinbase']) <= 100):
            raise ValueError('''bad coinbase size! %i bytes''' % (
                len(self.share_info['share_data']['coinbase']),))

        assert not self.hash_link['extra_data'], repr(
            self.hash_link['extra_data'])

        self.share_data = self.share_info['share_data']
        self.max_target = self.share_info['max_bits'].target
        self.target = self.share_info['bits'].target
        self.timestamp = self.share_info['timestamp']
        self.previous_hash = self.share_data['previous_share_hash']
        if self.VERSION >= 34:
            self.new_script = bitcoin_data.address_to_script2(
                self.share_data['address'], net.PARENT)
            self.address = self.share_data['address']
        else:
            self.new_script = bitcoin_data.pubkey_hash_to_script2(
                self.share_data['pubkey_hash'],
                net.PARENT.ADDRESS_VERSION, -1, net.PARENT)
            self.address = bitcoin_data.pubkey_hash_to_address(
                self.share_data['pubkey_hash'],
                net.PARENT.ADDRESS_VERSION, -1, net.PARENT)
        self.desired_version = self.share_data['desired_version']
        self.absheight = self.share_info['absheight']
        self.abswork = self.share_info['abswork']
        if net.NAME == 'bitcoin' and self.absheight > 3927800 and self.desired_version == 16:
            raise ValueError("This is not a hardfork-supporting share!")

        if self.VERSION < 34:
            n = set()
            for share_count, tx_count in self.iter_transaction_hash_refs():
                assert share_count < 110
                if share_count == 0:
                    n.add(tx_count)
            assert n == set(
                range(len(self.share_info['new_transaction_hashes'])))

        self.gentx_hash = check_hash_link(
            self.hash_link,
            self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(
                64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
            self.gentx_before_refhash,
        )
        merkle_root = bitcoin_data.check_merkle_link(
            self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
        self.header = dict(self.min_header, merkle_root=merkle_root)
        self.pow_hash = net.PARENT.POW_FUNC(
            bitcoin_data.block_header_type.pack(self.header))
        self.hash = self.header_hash = bitcoin_data.hash256(
            bitcoin_data.block_header_type.pack(self.header))

        if self.target > net.MAX_TARGET:
            from p2pool import p2p
            raise p2p.PeerMisbehavingError('share target invalid')

        if self.pow_hash > self.target:
            from p2pool import p2p
            raise p2p.PeerMisbehavingError('share PoW invalid')

        if self.VERSION < 34:
            self.new_transaction_hashes = self.share_info['new_transaction_hashes']

        # XXX eww
        self.time_seen = time.time()

        */
    }
    
    private:
    newType5 __repr__(self){
        /*
        def __repr__(self):
        return 'Share' + repr((self.net, self.peer_addr, self.contents))
        */
    }
    

    newType5 as_share(self){
        /*
        def as_share(self):
        return dict(type=self.VERSION, contents=self.share_type.pack(self.contents))
        */
    }
    
    newType6 iter_transaction_hash_refs(self){
        /*
            def iter_transaction_hash_refs(self):
        try:
            return zip(self.share_info['transaction_hash_refs'][::2], self.share_info['transaction_hash_refs'][1::2])
        except AttributeError:
            return zip()
        except KeyError:
            return zip()
        */
    }

    newType7 check(self, tracker, known_txs=None, block_abs_height_func=None, feecache=None){
        /*
        def check(self, tracker, known_txs=None, block_abs_height_func=None, feecache=None):
        from p2pool import p2p
        if self.timestamp > int(time.time()) + 600:
            raise ValueError("Share timestamp is %i seconds in the future! Check your system clock." %
                             self.timestamp - int(time.time()))
        counts = None
        if self.share_data['previous_share_hash'] is not None and block_abs_height_func is not None:
            previous_share = tracker.items[self.share_data['previous_share_hash']]
            if tracker.get_height(self.share_data['previous_share_hash']) >= self.net.CHAIN_LENGTH:
                counts = get_desired_version_counts(tracker, tracker.get_nth_parent_hash(
                    previous_share.hash, self.net.CHAIN_LENGTH*9//10), self.net.CHAIN_LENGTH//10)
                if type(self) is type(previous_share):
                    pass
                elif type(self) is type(previous_share).SUCCESSOR:
                    # switch only valid if 60% of hashes in [self.net.CHAIN_LENGTH*9//10, self.net.CHAIN_LENGTH] for new version
                    if counts.get(self.VERSION, 0) < sum(counts.itervalues())*60//100:
                        raise p2p.PeerMisbehavingError(
                            'switch without enough hash power upgraded')
                else:
                    raise p2p.PeerMisbehavingError('''%s can't follow %s''' % (
                        type(self).__name__, type(previous_share).__name__))
            elif type(self) is type(previous_share).SUCCESSOR:
                raise p2p.PeerMisbehavingError('switch without enough history')

        if self.VERSION < 34:
            other_tx_hashes = [tracker.items[tracker.get_nth_parent_hash(
                self.hash, share_count)].share_info['new_transaction_hashes'][tx_count] for share_count, tx_count in self.iter_transaction_hash_refs()]
        else:
            other_tx_hashes = []
        if known_txs is not None and not isinstance(known_txs, dict):
            print "Performing maybe-unnecessary packing and hashing"
            known_txs = dict((bitcoin_data.hash256(
                bitcoin_data.tx_type.pack(tx)), tx) for tx in known_txs)

        share_info, gentx, other_tx_hashes2, get_share = self.generate_transaction(tracker, self.share_info['share_data'], self.header['bits'].target, self.share_info['timestamp'], self.share_info['bits'].target, self.contents['ref_merkle_link'], [(h, None) for h in other_tx_hashes], self.net,
                                                                                   known_txs=None, last_txout_nonce=self.contents['last_txout_nonce'], segwit_data=self.share_info.get('segwit_data', None))

        if self.VERSION < 34:
            # check for excessive fees
            if self.share_data['previous_share_hash'] is not None and block_abs_height_func is not None:
                height = (block_abs_height_func(
                    self.header['previous_block'])+1)
                base_subsidy = self.net.PARENT.SUBSIDY_FUNC(height)
                fees = [feecache[x] for x in other_tx_hashes if x in feecache]
                missing = sum(
                    [1 for x in other_tx_hashes if not x in feecache])
                if missing == 0:
                    max_subsidy = sum(fees) + base_subsidy
                    details = "Max allowed = %i, requested subsidy = %i, share hash = %064x, miner = %s" % (
                        max_subsidy, self.share_data['subsidy'], self.hash,
                        self.address)
                    if self.share_data['subsidy'] > max_subsidy:
                        self.naughty = 1
                        print "Excessive block reward in share! Naughty. " + details
                    elif self.share_data['subsidy'] < max_subsidy:
                        print "Strange, we received a share that did not include as many coins in the block reward as was allowed. "
                        print "While permitted by the protocol, this causes coins to be lost forever if mined as a block, and costs us money."
                        print details

        if self.share_data['previous_share_hash'] and tracker.items[self.share_data['previous_share_hash']].naughty:
            print "naughty ancestor found %i generations ago" % tracker.items[
                self.share_data['previous_share_hash']].naughty
            # I am not easily angered ...
            print "I will not fail to punish children and grandchildren to the third and fourth generation for the sins of their parents."
            self.naughty = 1 + \
                tracker.items[self.share_data['previous_share_hash']].naughty
            if self.naughty > 6:
                self.naughty = 0

        assert other_tx_hashes2 == other_tx_hashes
        if share_info != self.share_info:
            raise ValueError('share_info invalid')
        if bitcoin_data.get_txid(gentx) != self.gentx_hash:
            raise ValueError('''gentx doesn't match hash_link''')
        if self.VERSION < 34:
            # the other hash commitments are checked in the share_info assertion
            if bitcoin_data.calculate_merkle_link([None] + other_tx_hashes, 0) != self.merkle_link:
                raise ValueError(
                    'merkle_link and other_tx_hashes do not match')

        update_min_protocol_version(counts, self)

        self.gentx_size = len(bitcoin_data.tx_id_type.pack(gentx))
        self.gentx_weight = len(
            bitcoin_data.tx_type.pack(gentx)) + 3*self.gentx_size

        # saving this share's gentx size as a class variable is an ugly hack, and you're welcome to hate me for doing it. But it works.
        type(self).gentx_size = self.gentx_size
        type(self).gentx_weight = self.gentx_weight

        _diff = self.net.PARENT.DUMB_SCRYPT_DIFF*float(
            bitcoin_data.target_to_difficulty(self.target))
        if not self.naughty:
            print("Received good share: diff=%.2e hash=%064x miner=%s" %
                  (_diff, self.hash, self.address))
        else:
            print("Received naughty=%i share: diff=%.2e hash=%064x miner=%s" %
                  (self.naughty, _diff, self.hash, self.address))
        return gentx  # only used by as_block
        */
    }

    newType8 get_other_tx_hashes(self, tracker){
        /*
        def get_other_tx_hashes(self, tracker):
        parents_needed = max(share_count for share_count, tx_count in self.iter_transaction_hash_refs(
        )) if self.share_info.get('transaction_hash_refs', None) else 0
        parents = tracker.get_height(self.hash) - 1
        if parents < parents_needed:
            return None
        last_shares = list(tracker.get_chain(self.hash, parents_needed + 1))
        ret = []
        for share_count, tx_count in self.iter_transaction_hash_refs():
            try:
                ret.append(last_shares[share_count]
                           .share_info['new_transaction_hashes'][tx_count])
            except AttributeError:
                continue
        return ret
        */
    }

    private:
    newType9 _get_other_txs(self, tracker, known_txs){
        /*
        def _get_other_txs(self, tracker, known_txs):
        other_tx_hashes = self.get_other_tx_hashes(tracker)
        if other_tx_hashes is None:
            return None  # not all parents present

        if not all(tx_hash in known_txs for tx_hash in other_tx_hashes):
            return None  # not all txs present

        return [known_txs[tx_hash] for tx_hash in other_tx_hashes]
        */
    }

    newType10 should_punish_reason(self, previous_block, bits, tracker, known_txs){
        /*
        def should_punish_reason(self, previous_block, bits, tracker, known_txs): #TODO
        if self.pow_hash <= self.header['bits'].target:
            return -1, 'block solution'
        if self.naughty == 1:
            return self.naughty, 'naughty share (excessive block reward or otherwise would make an invalid block)'
        if self.naughty:
            return self.naughty, 'descendent of naughty share                                                    '
        if self.VERSION < 34:
            other_txs = self._get_other_txs(tracker, known_txs)
        else:
            other_txs = None
        if other_txs is None:
            pass
        else:
            if not hasattr(self, 'all_tx_size'):
                self.all_txs_size = sum(bitcoin_data.get_size(tx)
                                        for tx in other_txs)
                self.stripped_txs_size = sum(
                    bitcoin_data.get_stripped_size(tx) for tx in other_txs)
            if self.all_txs_size + 3 * self.stripped_txs_size + 4*80 + self.gentx_weight > tracker.net.BLOCK_MAX_WEIGHT:
                return True, 'txs over block weight limit'
            if self.stripped_txs_size + 80 + self.gentx_size > tracker.net.BLOCK_MAX_SIZE:
                return True, 'txs over block size limit'

        return False, None
        */
    }

    newType11 as_block(self, tracker, known_txs){
        /*
        def as_block(self, tracker, known_txs):
        other_txs = self._get_other_txs(tracker, known_txs)
        if other_txs is None:
            return None  # not all txs present
        return dict(header=self.header, txs=[self.check(tracker, other_txs)] + other_txs) */
    }

    

}