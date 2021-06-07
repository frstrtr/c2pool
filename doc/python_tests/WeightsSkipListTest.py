import math_imported as math
import itertools


_nothing = object()

class LRUDict(object):
    def __init__(self, n):
        self.n = n
        self.inner = {}
        self.counter = itertools.count()
    def get(self, key, default=None):
        if key in self.inner:
            x, value = self.inner[key]
            self.inner[key] = self.counter.next(), value
            return value
        return default
    def __setitem__(self, key, value):
        self.inner[key] = self.counter.next(), value
        while len(self.inner) > self.n:
            self.inner.pop(min(self.inner, key=lambda k: self.inner[k][0]))

def memoize_with_backing(backing, has_inverses=set()):
    def a(f):
        def b(*args):
            res = backing.get((f, args), _nothing)
            if res is not _nothing:
                return res
            
            res = f(*args)
            
            backing[(f, args)] = res
            for inverse in has_inverses:
                backing[(inverse, args[:-1] + (res,))] = args[-1]
            
            return res
        return b
    return a

def target_to_average_attempts(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2**256: warnings.warn('target >= 2**256!')
    return 2**256//(target + 1)


class SkipList(object):
    def __init__(self, p=0.5):
        self.p = p
        
        self.skips = {}
    
    def forget_item(self, item):
        self.skips.pop(item, None)
    
    memoize_with_backing(LRUDict(5))
    def __call__(self, start, *args):
        updates = {}
        pos = start
        sol = self.initial_solution(start, args)
        if self.judge(sol, args) == 0:
            return self.finalize(sol, args)
        while True:
            if pos not in self.skips:
                self.skips[pos] = math.geometric(self.p), [(self.previous(pos), self.get_delta(pos))]
            skip_length, skip = self.skips[pos]
            
            # fill previous updates
            for i in xrange(skip_length):
                if i in updates:
                    that_hash, delta = updates.pop(i)
                    x, y = self.skips[that_hash]
                    assert len(y) == i
                    y.append((pos, delta))
            
            # put desired skip nodes in updates
            for i in xrange(len(skip), skip_length):
                updates[i] = pos, None
            
            #if skip_length + 1 in updates:
            #    updates[skip_length + 1] = self.combine(updates[skip_length + 1], updates[skip_length])
            
            for jump, delta in reversed(skip):
                sol_if = self.apply_delta(sol, delta, args)
                decision = self.judge(sol_if, args)
                #print pos, sol, jump, delta, sol_if, decision
                if decision == 0:
                    return self.finalize(sol_if, args)
                elif decision < 0:
                    sol = sol_if
                    break
            else:
                raise AssertionError()
            
            sol = sol_if
            pos = jump
            
            # XXX could be better by combining updates
            for x in updates:
                updates[x] = updates[x][0], self.combine_deltas(updates[x][1], delta) if updates[x][1] is not None else delta
    
    def finalize(self, sol, args):
        return sol


class TrackerSkipList(SkipList):
    def __init__(self, tracker):
        SkipList.__init__(self)
        self.tracker = tracker
        
        #self.tracker.removed.watch_weakref(self, lambda self, item: self.forget_item(item.hash))
    
    def previous(self, element):
        #return previous share hash
        #return self.tracker._delta_type.from_element(self.tracker.items[element]).tail
        return element-1

class WeightsSkipList(TrackerSkipList):
    # share_count, weights, total_weight
    
    def get_delta(self, element):
        share = self.tracker.items[element]
        att = target_to_average_attempts(share.target)
        return 1, {share.new_script: att*(65535-share.share_data['donation'])}, att*65535, att*share.share_data['donation']
    
    def combine_deltas(self, (share_count1, weights1, total_weight1, total_donation_weight1), (share_count2, weights2, total_weight2, total_donation_weight2)):
        return share_count1 + share_count2, math.add_dicts(weights1, weights2), total_weight1 + total_weight2, total_donation_weight1 + total_donation_weight2
    
    def initial_solution(self, start, (max_shares, desired_weight)):
        assert desired_weight % 65535 == 0, divmod(desired_weight, 65535)
        return 0, None, 0, 0
    
    def apply_delta(self, (share_count1, weights_list, total_weight1, total_donation_weight1), (share_count2, weights2, total_weight2, total_donation_weight2), (max_shares, desired_weight)):
        if total_weight1 + total_weight2 > desired_weight and share_count2 == 1:
            assert (desired_weight - total_weight1) % 65535 == 0
            script, = weights2.iterkeys()
            new_weights = {script: (desired_weight - total_weight1)//65535*weights2[script]//(total_weight2//65535)}
            return share_count1 + share_count2, (weights_list, new_weights), desired_weight, total_donation_weight1 + (desired_weight - total_weight1)//65535*total_donation_weight2//(total_weight2//65535)
        return share_count1 + share_count2, (weights_list, weights2), total_weight1 + total_weight2, total_donation_weight1 + total_donation_weight2
    
    def judge(self, (share_count, weights_list, total_weight, total_donation_weight), (max_shares, desired_weight)):
        if share_count > max_shares or total_weight > desired_weight:
            return 1
        elif share_count == max_shares or total_weight == desired_weight:
            return 0
        else:
            return -1
    
    def finalize(self, (share_count, weights_list, total_weight, total_donation_weight), (max_shares, desired_weight)):
        assert share_count <= max_shares and total_weight <= desired_weight
        assert share_count == max_shares or total_weight == desired_weight
        return math.add_dicts(*math.flatten_linked_list(weights_list)), total_weight, total_donation_weight


get_cumulative_weights = WeightsSkipList()

# weights, total_weight, donation_weight = get_cumulative_weights(previous_share.share_data['previous_share_hash'] if previous_share is not None else None,
#             max(0, min(height, net.REAL_CHAIN_LENGTH) - 1),
#             65535*net.SPREAD*bitcoin_data.target_to_average_attempts(block_target),
#         )
REAL_CHAIN_LENGTH = 24*60*60//10
SPREAD = 200
previous_share_hash = 1337
block_target = int("0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)


weights, total_weight, donation_weight = get_cumulative_weights(previous_share_hash,
            max(0, REAL_CHAIN_LENGTH - 1),
            65535*SPREAD*target_to_average_attempts(block_target),
        )