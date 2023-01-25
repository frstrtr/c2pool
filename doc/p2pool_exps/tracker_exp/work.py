from __future__ import division
from collections import deque

import base64
import random
import re
import sys
import time

from twisted.internet import defer
from twisted.python import log

import coind_data as bitcoin_data
# import bitcoin.getwork as bitcoin_getwork
import coind_worker_interface
import script
# from bitcoin import helper
import tracker
# import jsonrpc, deferral
import variable, p2pool_math, pack
import data as p2pool_data
import share

print_throttle = 0.0
DEBUG = True
BENCH = True

class WorkerBridge(coind_worker_interface.WorkerBridge):
    COINBASE_NONCE_LENGTH = 8
    
    def __init__(self, node, my_pubkey_hash, donation_percentage, worker_fee, pubkeys):
        coind_worker_interface.WorkerBridge.__init__(self)
        self.recent_shares_ts_work = []
        
        self.node = node

        # self.bitcoind = bitcoind
        self.pubkeys = pubkeys
        # self.args = args
        self.my_pubkey_hash = my_pubkey_hash

        self.donation_percentage = 0.0
        self.worker_fee = 0
        
        self.net = self.node.net.PARENT
        self.running = True
        self.pseudoshare_received = variable.Event()
        self.share_received = variable.Event()
        self.local_rate_monitor = p2pool_math.RateMonitor(10*60)
        self.local_addr_rate_monitor = p2pool_math.RateMonitor(10*60)
        
        self.removed_unstales_var = variable.Variable((0, 0, 0))
        self.removed_doa_unstales_var = variable.Variable(0)
        
        self.last_work_shares = variable.Variable( {} )
        self.my_share_hashes = set()
        self.my_doa_share_hashes = set()

        self.address_throttle = 0
        
        self.tracker_view = tracker.TrackerView(self.node.tracker, tracker.get_attributedelta_type(dict(tracker.AttributeDelta.attrs,
            my_count=lambda share: 1 if share.hash in self.my_share_hashes else 0,
            my_doa_count=lambda share: 1 if share.hash in self.my_doa_share_hashes else 0,
            my_orphan_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'orphan' else 0,
            my_dead_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'doa' else 0,
        )))
        
        @self.node.tracker.verified.removed.watch
        def _(share):
            if share.hash in self.my_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                assert share.share_data['stale_info'] in [None, 'orphan', 'doa'] # we made these shares in this instance
                self.removed_unstales_var.set((
                    self.removed_unstales_var.value[0] + 1,
                    self.removed_unstales_var.value[1] + (1 if share.share_data['stale_info'] == 'orphan' else 0),
                    self.removed_unstales_var.value[2] + (1 if share.share_data['stale_info'] == 'doa' else 0),
                ))
            if share.hash in self.my_doa_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                self.removed_doa_unstales_var.set(self.removed_doa_unstales_var.value + 1)
        
        # MERGED WORK
        
        # self.merged_work = variable.Variable({})
        
        # @defer.inlineCallbacks
        # def set_merged_work(merged_url, merged_userpass):
        #     merged_proxy = jsonrpc.HTTPProxy(merged_url, dict(Authorization='Basic ' + base64.b64encode(merged_userpass)))
        #     while self.running:
        #         auxblock = yield deferral.retry('Error while calling merged getauxblock on %s:' % (merged_url,), 30)(merged_proxy.rpc_getauxblock)()
        #         target = auxblock['target'] if 'target' in auxblock else auxblock['_target']
        #         self.merged_work.set(math.merge_dicts(self.merged_work.value, {auxblock['chainid']: dict(
        #             hash=int(auxblock['hash'], 16),
        #             target='p2pool' if target == 'p2pool' else pack.IntType(256).unpack(target.decode('hex')),
        #             merged_proxy=merged_proxy,
        #         )}))
        #         yield deferral.sleep(1)
        # for merged_url, merged_userpass in merged_urls:
        #     set_merged_work(merged_url, merged_userpass)
        
        # @self.merged_work.changed.watch
        # def _(new_merged_work):
        #     print 'Got new merged mining work!'
        
        # COMBINE WORK
        #TODO:
        self.current_work = variable.Variable(None)
        def compute_work():
            t = self.node.bitcoind_work.value
            bb = self.node.best_block_header.value
            if bb is not None and bb['previous_block'] == t['previous_block'] and self.node.net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(bb)) <= t['bits'].target:
                print 'Skipping from block %x to block %x!' % (bb['previous_block'],
                    bitcoin_data.hash256(bitcoin_data.block_header_type.pack(bb)))
                t = dict(
                    version=bb['version'],
                    previous_block=bitcoin_data.hash256(bitcoin_data.block_header_type.pack(bb)),
                    bits=bb['bits'], # not always true
                    coinbaseflags='',
                    height=t['height'] + 1,
                    time=max(int(time.time() + 0.5), bb['timestamp'] + 1),
                    transactions=[],
                    transaction_fees=[],
                    merkle_link=bitcoin_data.calculate_merkle_link([None], 0),
                    subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.node.bitcoind_work.value['height']),
                    last_update=self.node.bitcoind_work.value['last_update'],
                )
            
            self.current_work.set(t)
        self.node.bitcoind_work.changed.watch(lambda _: compute_work())
        self.node.best_block_header.changed.watch(lambda _: compute_work())
        compute_work()
        
        # self.new_work_event = variable.Event()
        # @self.current_work.transitioned.watch
        # def _(before, after):
        #     # trigger LP if version/previous_block/bits changed or transactions changed from nothing
        #     if any(before[x] != after[x] for x in ['version', 'previous_block', 'bits']) or (not before['transactions'] and after['transactions']):
        #         self.new_work_event.happened()
        # self.merged_work.changed.watch(lambda _: self.new_work_event.happened())
        # self.node.best_share_var.changed.watch(lambda _: self.new_work_event.happened())
    
    def stop(self):
        self.running = False
    
    def get_stale_counts(self):
        '''Returns (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain)'''
        my_shares = len(self.my_share_hashes)
        my_doa_shares = len(self.my_doa_share_hashes)
        delta = self.tracker_view.get_delta_to_last(self.node.best_share_var.value)
        my_shares_in_chain = delta.my_count + self.removed_unstales_var.value[0]
        my_doa_shares_in_chain = delta.my_doa_count + self.removed_doa_unstales_var.value
        orphans_recorded_in_chain = delta.my_orphan_announce_count + self.removed_unstales_var.value[1]
        doas_recorded_in_chain = delta.my_dead_announce_count + self.removed_unstales_var.value[2]
        
        my_shares_not_in_chain = my_shares - my_shares_in_chain
        my_doa_shares_not_in_chain = my_doa_shares - my_doa_shares_in_chain
        
        return (my_shares_not_in_chain - my_doa_shares_not_in_chain, my_doa_shares_not_in_chain), my_shares, (orphans_recorded_in_chain, doas_recorded_in_chain)
    
    # @defer.inlineCallbacks
    # def freshen_addresses(self, c):
    #     self.cur_address_throttle = time.time()
    #     if self.cur_address_throttle - self.address_throttle < 30:
    #         return
    #     self.address_throttle=time.time()
    #     print "ATTEMPTING TO FRESHEN ADDRESS."
    #     self.address = yield deferral.retry('Error getting a dynamic address from bitcoind:', 5)(lambda: self.bitcoind.rpc_getnewaddress('p2pool'))()
    #     new_pubkey = bitcoin_data.address_to_pubkey_hash(self.address, self.net)
    #     self.pubkeys.popleft()
    #     self.pubkeys.addkey(new_pubkey)
    #     print " Updated payout pool:"
    #     for i in range(len(self.pubkeys.keys)):
    #         print '    ...payout %d: %s(%f)' % (i, bitcoin_data.pubkey_hash_to_address(self.pubkeys.keys[i], self.net),self.pubkeys.keyweights[i],)
    #     self.pubkeys.updatestamp(c)
    #     print " Next address rotation in : %fs" % (time.time()-c+self.args.timeaddresses)
 
    def get_user_details(self, username):
        contents = re.split('([+/])', username)
        assert len(contents) % 2 == 1
        
        user, contents2 = contents[0].strip(), contents[1:]
        
        desired_pseudoshare_target = None
        desired_share_target = None
        for symbol, parameter in zip(contents2[::2], contents2[1::2]):
            if symbol == '+':
                try:
                    desired_pseudoshare_target = bitcoin_data.difficulty_to_target(float(parameter))
                except:
                    print('exc1')
            elif symbol == '/':
                try:
                    desired_share_target = bitcoin_data.difficulty_to_target(float(parameter))
                except:
                    print('exc2')

        # if self.args.address == 'dynamic':
        #     i = self.pubkeys.weighted()
        #     pubkey_hash = self.pubkeys.keys[i]

        #     c = time.time()
        #     if (c - self.pubkeys.stamp) > self.args.timeaddresses:
        #         self.freshen_addresses(c)

        if random.uniform(0, 100) < self.worker_fee:
            pubkey_hash = self.my_pubkey_hash
        else:
            try:
                pubkey_hash = bitcoin_data.address_to_pubkey_hash(user, self.node.net.PARENT)
            except: # XXX blah
                pubkey_hash = int('78ecd67a8695aa4adc55b70f87c2fa3279cee6d0', 16)
                # if self.args.address != 'dynamic':
                #     pubkey_hash = self.my_pubkey_hash
        
        return user, pubkey_hash, desired_share_target, desired_pseudoshare_target
    
    def preprocess_request(self, user):
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            raise BaseException('p2pool is not connected to any peers')
            # raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
        if time.time() > self.current_work.value['last_update'] + 60:
            pass
            #REMOVED
            # raise BaseException('lost contact with bitcoind')
            # raise jsonrpc.Error_for_code(-12345)(u'lost contact with bitcoind')
        user, pubkey_hash, desired_share_target, desired_pseudoshare_target = self.get_user_details(user)
        return user, pubkey_hash, desired_share_target, desired_pseudoshare_target
        #return pubkey_hash, desired_share_target, desired_pseudoshare_target
    
    def _estimate_local_hash_rate(self):
        if len(self.recent_shares_ts_work) == 50:
            hash_rate = sum(work for ts, work in self.recent_shares_ts_work[1:])//(self.recent_shares_ts_work[-1][0] - self.recent_shares_ts_work[0][0])
            if hash_rate > 0:
                return hash_rate
        return None
    
    def get_local_rates(self):
        miner_hash_rates = {}
        miner_dead_hash_rates = {}
        datums, dt = self.local_rate_monitor.get_datums_in_last()
        for datum in datums:
            miner_hash_rates[datum['user']] = miner_hash_rates.get(datum['user'], 0) + datum['work']/dt
            if datum['dead']:
                miner_dead_hash_rates[datum['user']] = miner_dead_hash_rates.get(datum['user'], 0) + datum['work']/dt
        return miner_hash_rates, miner_dead_hash_rates
    
    def get_local_addr_rates(self):
        addr_hash_rates = {}
        datums, dt = self.local_addr_rate_monitor.get_datums_in_last()
        for datum in datums:
            addr_hash_rates[datum['pubkey_hash']] = addr_hash_rates.get(datum['pubkey_hash'], 0) + datum['work']/dt
        return addr_hash_rates
 
    def get_work(self, pubkey_hash, desired_share_target, desired_pseudoshare_target, worker_ip=None):
        global print_throttle
        #1
        t0 = time.time()
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            # raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
            raise BaseException('p2pool is not connected to any peers')
        if self.node.best_share_var.value is None and self.node.net.PERSIST:
            raise BaseException('p2pool is downloading shares')
            # raise jsonrpc.Error_for_code(-12345)(u'p2pool is downloading shares')
        # unknown_rules = set(r[1:] if r.startswith('!') else r for r in self.node.bitcoind_work.value['rules']) - set(getattr(self.node.net, 'SOFTFORKS_REQUIRED', []))
        # if unknown_rules:
        #     print "Unknown softforks found: ", unknown_rules
        #     # raise jsonrpc.Error_for_code(-12345)(u'unknown rule activated')
        #     raise BaseException("unknown rule activated")
        
        #2: NOW IGNORED FOR C2POOL!!!
        # if self.merged_work.value:
        #     tree, size = bitcoin_data.make_auxpow_tree(self.merged_work.value)
        #     mm_hashes = [self.merged_work.value.get(tree.get(i), dict(hash=0))['hash'] for i in xrange(size)]
        #     mm_data = '\xfa\xbemm' + bitcoin_data.aux_pow_coinbase_type.pack(dict(
        #         merkle_root=bitcoin_data.merkle_hash(mm_hashes),
        #         size=size,
        #         nonce=0,
        #     ))
        #     mm_later = [(aux_work, mm_hashes.index(aux_work['hash']), mm_hashes) for chain_id, aux_work in self.merged_work.value.iteritems()]
        # else:
        #     mm_data = ''
        #     mm_later = []
        
        #3
        tx_hashes = [bitcoin_data.hash256(bitcoin_data.tx_type.pack(tx)) for tx in self.current_work.value['transactions']]
        tx_map = dict(zip(tx_hashes, self.current_work.value['transactions']))

        self.node.mining2_txs_var.set(tx_map) # let node.py know not to evict these transactions
        
        #4
        previous_share = self.node.tracker.items[self.node.best_share_var.value] if self.node.best_share_var.value is not None else None
        if previous_share is None:
            share_type = p2pool_data.Share
        else:
            previous_share_type = type(previous_share)
            
            if previous_share_type.SUCCESSOR is None or self.node.tracker.get_height(previous_share.hash) < self.node.net.CHAIN_LENGTH:
                share_type = previous_share_type
            else:
                successor_type = previous_share_type.SUCCESSOR
                
                counts = p2pool_data.get_desired_version_counts(self.node.tracker,
                    self.node.tracker.get_nth_parent_hash(previous_share.hash, self.node.net.CHAIN_LENGTH*9//10), self.node.net.CHAIN_LENGTH//10)
                upgraded = counts.get(successor_type.VERSION, 0)/sum(counts.itervalues())
                if upgraded > .65:
                    print 'Switchover imminent. Upgraded: %.3f%% Threshold: %.3f%%' % (upgraded*100, 95)
                # Share -> NewShare only valid if 95% of hashes in [net.CHAIN_LENGTH*9//10, net.CHAIN_LENGTH] for new version
                if counts.get(successor_type.VERSION, 0) > sum(counts.itervalues())*95//100:
                    share_type = successor_type
                else:
                    share_type = previous_share_type
        
        #5
        local_addr_rates = self.get_local_addr_rates()
	
        if desired_share_target is None:
            desired_share_target = bitcoin_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
            local_hash_rate = local_addr_rates.get(pubkey_hash, 0)
            if local_hash_rate > 0.0:
                desired_share_target = min(desired_share_target,
                    bitcoin_data.average_attempts_to_target(local_hash_rate * self.node.net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
            
            lookbehind = 3600//self.node.net.SHARE_PERIOD
            block_subsidy = self.node.bitcoind_work.value['subsidy']
            if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
                expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/share.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
                    * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
                if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
                    desired_share_target = min(desired_share_target,
                        bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
                    )
        
        #6
        if True:
            share_info, gentx, other_transaction_hashes, get_share = share_type.generate_transaction(
                tracker=self.node.tracker,
                share_data=dict(
                    previous_share_hash=self.node.best_share_var.value,
                    coinbase=(script.create_push_script([
                        self.current_work.value['height'],
                         ] +
                        #   ([mm_data] if mm_data else []) + 
                          []) + self.current_work.value['coinbaseflags'])[:100],
                    nonce=random.randrange(2**32),
                    pubkey_hash=pubkey_hash,
                    subsidy=self.current_work.value['subsidy'],
                    donation=p2pool_math.perfect_round(65535*self.donation_percentage/100),
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
                net=self.node.net,
                known_txs=tx_map,
                base_subsidy="fake_subsidy"#self.node.net.PARENT.SUBSIDY_FUNC(self.current_work.value['height']),
            )
        
        #7
        print('GENTX: {0}'.format(gentx))
        packed_gentx = bitcoin_data.tx_id_type.pack(gentx) # stratum miners work with stripped transactions
        other_transactions = [tx_map[tx_hash] for tx_hash in other_transaction_hashes]
        
        #8
        # mm_later = [(dict(aux_work, target=aux_work['target'] if aux_work['target'] != 'p2pool' else share_info['bits'].target), index, hashes) for aux_work, index, hashes in mm_later]
        
        if desired_pseudoshare_target is None:
            target = bitcoin_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
            local_hash_rate = self._estimate_local_hash_rate()
            if local_hash_rate is not None:
                target = bitcoin_data.average_attempts_to_target(local_hash_rate * 1) # target 10 share responses every second by modulating pseudoshare difficulty
            else:
                # If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
                # Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
                # 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
                # one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
                # every ~0.01 seconds.
                target = min(target, 3000 * bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(
                    self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy))
        else:
            target = desired_pseudoshare_target
        target = max(target, share_info['bits'].target)
        # for aux_work, index, hashes in mm_later:
        #     target = max(target, aux_work['target'])
        target = p2pool_math.clip(target, self.node.net.PARENT.SANE_TARGET_RANGE)
        
        #9
        getwork_time = time.time()
        lp_count = self.new_work_event.times
        merkle_link = bitcoin_data.calculate_merkle_link([None] + other_transaction_hashes, 0) if share_info.get('segwit_data', None) is None else share_info['segwit_data']['txid_merkle_link']
        
        if print_throttle is 0.0:
            print_throttle = time.time()
        else:
            current_time = time.time()
            if (current_time - print_throttle) > 5.0:
                print 'New work for %s! Diff: %.02f Share diff: %.02f Block value: %.2f %s (%i tx, %.0f kB)' % (
                    bitcoin_data.pubkey_hash_to_address(pubkey_hash, self.node.net.PARENT),
                    bitcoin_data.target_to_difficulty(target),
                    bitcoin_data.target_to_difficulty(share_info['bits'].target),
                    self.current_work.value['subsidy']*1e-8, self.node.net.PARENT.SYMBOL,
                    len(self.current_work.value['transactions']),
                    sum(map(bitcoin_data.tx_type.packed_size, self.current_work.value['transactions']))/1000.,
                )
                print_throttle = time.time()

        #need this for stats
        self.last_work_shares.value[bitcoin_data.pubkey_hash_to_address(pubkey_hash, self.node.net.PARENT)]=share_info['bits']
        
        #10 
        ba = dict(
            version=max(self.current_work.value['version'], 0x20000000),
            previous_block=self.current_work.value['previous_block'],
            merkle_link=merkle_link,
            coinb1=packed_gentx[:-self.COINBASE_NONCE_LENGTH-4],
            coinb2=packed_gentx[-4:],
            timestamp=self.current_work.value['time'],
            bits=self.current_work.value['bits'],
            share_target=target,
        )
        
        received_header_hashes = set()
        
        def got_response(header, user, coinbase_nonce):
            t0 = time.time()
            assert len(coinbase_nonce) == self.COINBASE_NONCE_LENGTH
            new_packed_gentx = packed_gentx[:-self.COINBASE_NONCE_LENGTH-4] + coinbase_nonce + packed_gentx[-4:] if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else packed_gentx
            new_gentx = bitcoin_data.tx_type.unpack(new_packed_gentx) if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else gentx
            if bitcoin_data.is_segwit_tx(gentx): # reintroduce witness data to the gentx produced by stratum miners
                new_gentx['marker'] = 0
                new_gentx['flag'] = gentx['flag']
                new_gentx['witness'] = gentx['witness']
            
            header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(header))
            pow_hash = self.node.net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(header))
            try:
                if pow_hash <= header['bits'].target or DEBUG:
                    helper.submit_block(dict(header=header, txs=[new_gentx] + other_transactions), False, self.node.factory, self.node.bitcoind, self.node.bitcoind_work, self.node.net)
                    if pow_hash <= header['bits'].target:
                        print
                        print 'GOT BLOCK FROM MINER! Passing to bitcoind! %s%064x' % (self.node.net.PARENT.BLOCK_EXPLORER_URL_PREFIX, header_hash)
                        print
            except:
                log.err(None, 'Error while processing potential block:')
            
            user, _, _, _ = self.get_user_details(user)
            assert header['previous_block'] == ba['previous_block']
            assert header['merkle_root'] == bitcoin_data.check_merkle_link(bitcoin_data.hash256(new_packed_gentx), merkle_link)
            assert header['bits'] == ba['bits']
            
            on_time = self.new_work_event.times == lp_count
            
            # for aux_work, index, hashes in mm_later:
            #     try:
            #         if pow_hash <= aux_work['target'] or DEBUG:
            #             df = deferral.retry('Error submitting merged block: (will retry)', 10, 10)(aux_work['merged_proxy'].rpc_getauxblock)(
            #                 pack.IntType(256, 'big').pack(aux_work['hash']).encode('hex'),
            #                 bitcoin_data.aux_pow_type.pack(dict(
            #                     merkle_tx=dict(
            #                         tx=new_gentx,
            #                         block_hash=header_hash,
            #                         merkle_link=merkle_link,
            #                     ),
            #                     merkle_link=bitcoin_data.calculate_merkle_link(hashes, index),
            #                     parent_block_header=header,
            #                 )).encode('hex'),
            #             )
            #             @df.addCallback
            #             def _(result, aux_work=aux_work):
            #                 if result != (pow_hash <= aux_work['target']):
            #                     print >>sys.stderr, 'Merged block submittal result: %s Expected: %s' % (result, pow_hash <= aux_work['target'])
            #                 else:
            #                     print 'Merged block submittal result: %s' % (result,)
            #             @df.addErrback
            #             def _(err):
            #                 log.err(err, 'Error submitting merged block:')
            #     except:
            #         log.err(None, 'Error while processing merged mining POW:')
            
            if pow_hash <= share_info['bits'].target and header_hash not in received_header_hashes:
                last_txout_nonce = pack.IntType(8*self.COINBASE_NONCE_LENGTH).unpack(coinbase_nonce)
                share = get_share(header, last_txout_nonce)
                
                print 'GOT SHARE! %s %s prev %s age %.2fs%s' % (
                    user,
                    p2pool_data.format_hash(share.hash),
                    p2pool_data.format_hash(share.previous_hash),
                    time.time() - getwork_time,
                    ' DEAD ON ARRIVAL' if not on_time else '',
                )

                # node.py will sometimes forget transactions if bitcoind's work has changed since this stratum
                # job was assigned. Fortunately, the tx_map is still in in our scope from this job, so we can use that
                # to refill it if needed.

                known_txs = self.node.known_txs_var.value
                missing = {hsh:val for (hsh, val) in tx_map.iteritems() if not hsh in known_txs}
                if missing:
                    print "Warning: %i transactions were erroneously evicted from known_txs_var. Refilling now." % len(missing)
                    self.node.known_txs_var.add(missing)

                self.my_share_hashes.add(share.hash)
                if not on_time:
                    self.my_doa_share_hashes.add(share.hash)
                
                self.node.tracker.add(share)
                self.node.set_best_share()
                
                try:
                    if (pow_hash <= header['bits'].target or DEBUG) and self.node.p2p_node is not None:
                        self.node.p2p_node.broadcast_share(share.hash)
                except:
                    log.err(None, 'Error forwarding block solution:')
                
                self.share_received.happened(bitcoin_data.target_to_average_attempts(share.target), not on_time, share.hash)
            
            if pow_hash > target:
                print 'Worker %s submitted share with hash > target:' % (user,)
                print '    Hash:   %56x' % (pow_hash,)
                print '    Target: %56x' % (target,)
            elif header_hash in received_header_hashes:
                print >>sys.stderr, 'Worker %s submitted share more than once!' % (user,)
            else:
                received_header_hashes.add(header_hash)
                
                self.pseudoshare_received.happened(bitcoin_data.target_to_average_attempts(target), not on_time, user)
                self.recent_shares_ts_work.append((time.time(), bitcoin_data.target_to_average_attempts(target)))
                while len(self.recent_shares_ts_work) > 50:
                    self.recent_shares_ts_work.pop(0)
                self.local_rate_monitor.add_datum(dict(work=bitcoin_data.target_to_average_attempts(target), dead=not on_time, user=user, share_target=share_info['bits'].target))
                self.local_addr_rate_monitor.add_datum(dict(work=bitcoin_data.target_to_average_attempts(target), pubkey_hash=pubkey_hash))
            t1 = time.time()
            if BENCH and (t1-t1) > .01: print "%8.3f ms for work.py:got_response()" % ((t1-t0)*1000.)

            return on_time
        t1 = time.time()
        if BENCH: print "%8.3f ms for work.py:get_work()" % ((t1-t0)*1000.)
        return ba, got_response