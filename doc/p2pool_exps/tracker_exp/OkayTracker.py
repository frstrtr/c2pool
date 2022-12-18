import tracker

import hashlib
import os
import random
import sys
import time
import array

import p2pool_math, coind_data

from twisted.python import log

def format_hash(x):
    if x is None:
        return 'xxxxxxxx'
    return '%08x' % (x % 2**32)

class OkayTracker(tracker.Tracker):
    def __init__(self, net):
        tracker.Tracker.__init__(self, delta_type=tracker.get_attributedelta_type(dict(tracker.AttributeDelta.attrs,
                                                                                     work=lambda share: coind_data.target_to_average_attempts(share.target),
                                                                                     min_work=lambda share: coind_data.target_to_average_attempts(share.max_target),
                                                                                     )))
        self.net = net
        self.verified = tracker.SubsetTracker(delta_type=tracker.get_attributedelta_type(dict(tracker.AttributeDelta.attrs,
                                                                                            work=lambda share: coind_data.target_to_average_attempts(share.target),
                                                                                            )), subset_of=self)
        self.get_cumulative_weights = tracker.WeightsSkipList(self)

    def attempt_verify(self, share):
        if share.hash in self.verified.items:
            return True
        height, last = self.get_height_and_last(share.hash)
        if height < self.net.CHAIN_LENGTH + 1 and last is not None:
            raise AssertionError()
        try:
            share.check(self)
        except:
            log.err(None, 'Share check failed: %064x -> %064x' % (share.hash, share.previous_hash if share.previous_hash is not None else 0))
            return False
        else:
            self.verified.add(share)
            return True

    def think(self, block_rel_height_func, previous_block, bits, known_txs):
        desired = set()
        bad_peer_addresses = set()

        # O(len(self.heads))
        #   make 'unverified heads' set?
        # for each overall head, attempt verification
        # if it fails, attempt on parent, and repeat
        # if no successful verification because of lack of parents, request parent
        bads = []
        print('heads - verified.heads = {0}'.format(len((set(self.heads) - set(self.verified.heads)))))
        for head in set(self.heads) - set(self.verified.heads):
            head_height, last = self.get_height_and_last(head)

            for share in self.get_chain(head, head_height if last is None else min(5, max(0, head_height - self.net.CHAIN_LENGTH))):
                if self.attempt_verify(share):
                    break
                bads.append(share.hash)
            else:
                if last is not None:
                    desired.add((
                        self.items[random.choice(list(self.reverse[last]))].peer_addr,
                        last,
                        max(x.timestamp for x in self.get_chain(head, min(head_height, 5))),
                        min(x.target for x in self.get_chain(head, min(head_height, 5))),
                    ))
        print('bads = {0}'.format(len(bads)))
        for bad in bads:
            assert bad not in self.verified.items
            #assert bad in self.heads
            bad_share = self.items[bad]
            if bad_share.peer_addr is not None:
                bad_peer_addresses.add(bad_share.peer_addr)
            if True:
                print "BAD", bad
            try:
                self.remove(bad)
            except NotImplementedError:
                pass

        print('self.verified.heads len = {0}'.format(len(self.verified.heads)))
        # try to get at least CHAIN_LENGTH height for each verified head, requesting parents if needed
        for head in list(self.verified.heads):
            head_height, last_hash = self.verified.get_height_and_last(head)
            last_height, last_last_hash = self.get_height_and_last(last_hash)
            # XXX review boundary conditions
            want = max(self.net.CHAIN_LENGTH - head_height, 0)
            can = max(last_height - 1 - self.net.CHAIN_LENGTH, 0) if last_last_hash is not None else last_height
            get = min(want, can)
            #print 'Z', head_height, last_hash is None, last_height, last_last_hash is None, want, can, get
            for share in self.get_chain(last_hash, get):
                if not self.attempt_verify(share):
                    break
            if head_height < self.net.CHAIN_LENGTH and last_last_hash is not None:
                desired.add((
                    self.items[random.choice(list(self.verified.reverse[last_hash]))].peer_addr,
                    last_last_hash,
                    max(x.timestamp for x in self.get_chain(head, min(head_height, 5))),
                    min(x.target for x in self.get_chain(head, min(head_height, 5))),
                ))

        # decide best tree
        
        for tail_hash in self.verified.tails:
            print('{0}:'.format(hex(tail_hash)))
            print(self.verified.tails[tail_hash])
            max_value = max(self.verified.tails[tail_hash], key=self.verified.get_work)
            print('max_value = {0}'.format(hex(max_value)))
            print(self.verified.get_height(max_value))
            

        decorated_tails = sorted((self.score(max(self.verified.tails[tail_hash], key=self.verified.get_work), block_rel_height_func), tail_hash) for tail_hash in self.verified.tails)
        if True:
            print len(decorated_tails), 'tails:'
            for score, tail_hash in decorated_tails:
                print format_hash(tail_hash), score
        best_tail_score, best_tail = decorated_tails[-1] if decorated_tails else (None, None)

        # decide best verified head
        decorated_heads = sorted(((
                                      self.verified.get_work(self.verified.get_nth_parent_hash(h, min(5, self.verified.get_height(h)))),
                                      #self.items[h].peer_addr is None,
                                      -self.items[h].should_punish_reason(previous_block, bits, self, known_txs)[0],
                                      -self.items[h].time_seen,
                                  ), h) for h in self.verified.tails.get(best_tail, []))
        if True:
            print len(decorated_heads), 'heads. Top 10:'
            for score, head_hash in decorated_heads[-10:]:
                print '   ', format_hash(head_hash), format_hash(self.items[head_hash].previous_hash), score
        best_head_score, best = decorated_heads[-1] if decorated_heads else (None, None)

        if best is not None:
            best_share = self.items[best]
            punish, punish_reason = best_share.should_punish_reason(previous_block, bits, self, known_txs)
            if punish > 0:
                print 'Punishing share for %r! Jumping from %s to %s!' % (punish_reason, format_hash(best), format_hash(best_share.previous_hash))
                best = best_share.previous_hash

            timestamp_cutoff = min(int(time.time()), best_share.timestamp) - 3600
            target_cutoff = int(2**256//(self.net.SHARE_PERIOD*best_tail_score[1] + 1) * 2 + .5) if best_tail_score[1] is not None else 2**256-1
        else:
            timestamp_cutoff = int(time.time()) - 24*60*60
            target_cutoff = 2**256-1

        if True:
            print 'Desire %i shares. Cutoff: %s old diff>%.2f' % (len(desired), p2pool_math.format_dt(time.time() - timestamp_cutoff), coind_data.target_to_difficulty(target_cutoff))
            for peer_addr, hash, ts, targ in desired:
                print '   ', None if peer_addr is None else '%s:%i' % peer_addr, format_hash(hash), p2pool_math.format_dt(time.time() - ts), coind_data.target_to_difficulty(targ), ts >= timestamp_cutoff, targ <= target_cutoff

        return best, [(peer_addr, hash) for peer_addr, hash, ts, targ in desired if ts >= timestamp_cutoff], decorated_heads, bad_peer_addresses

    def score(self, share_hash, block_rel_height_func):
        # returns approximate lower bound on chain's hashrate in the last self.net.CHAIN_LENGTH*15//16*self.net.SHARE_PERIOD time
        
        print("===SCORE BEGIN===")

        head_height = self.verified.get_height(share_hash)
        print('head_height: {0}'.format(head_height))
        if head_height < self.net.CHAIN_LENGTH:
            res = head_height, None
            print('res: {0}'.format(res))
            print("===SCORE FINISH1===")
            return res

        end_point = self.verified.get_nth_parent_hash(share_hash, self.net.CHAIN_LENGTH*15//16)

        block_height = max(block_rel_height_func(share.header['previous_block']) for share in
                           self.verified.get_chain(end_point, self.net.CHAIN_LENGTH//16))
        
        res = self.net.CHAIN_LENGTH, self.verified.get_delta(share_hash, end_point).work/((0 - block_height + 1)*self.net.PARENT.BLOCK_PERIOD)
        print('res: {0}'.format(res))
        print("===SCORE FINISH2===")
        return res