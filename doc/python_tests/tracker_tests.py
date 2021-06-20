class Share:
    def __init__(self, hash, prev_hash = None):
        self.hash = hash
        self.previous_hash =  hash-1 if prev_hash is None else prev_hash
        self.work = hash * 100

    @classmethod
    def get_none(cls, hash):
        res = Share(hash, hash)
        res.work = 0
        return res

    def __repr__(self):
        return "[{1}]<-[{0}]: {2}".format(self.hash, self.previous_hash, self.work)
        

class OkayTracker:

    def __init__(self, items = []):
        self.items = {}
        self.reverse = {}
        
        self.tails = {}
        self.heads = {}

        for item in items:
            self.add(item)

    def get_delta_to_last(self, item_hash): #@
        assert isinstance(item_hash, (int,  type(None)))
        delta = self.get_delta_none(item_hash)
        #updates = []
        while delta.tail in self.items:
            #updates.append((delta.tail, delta))
            this_delta = self.get_delta(self.items[delta.tail])
            delta += this_delta
        # for update_hash, delta_then in updates:
        #     self._set_delta(update_hash, delta - delta_then)
        return delta
    
    def get_height(self, item_hash):
        return self.get_delta_to_last(item_hash).height
    
    def get_work(self, item_hash):
        return self.get_delta_to_last(item_hash).work
    
    def get_last(self, item_hash):
        return self.get_delta_to_last(item_hash).tail

    def get_height_and_last(self, item_hash):
        delta = self.get_delta_to_last(item_hash)
        return delta.height, delta.tail

    #===from test
    # def get_height(self, item_hash):
    #     height, last = self.get_height_and_last(item_hash)
    #     return height
    
    # def get_last(self, item_hash):
    #     height, last = self.get_height_and_last(item_hash)
    #     return last
    
    # def get_height_and_last(self, item_hash):
    #     height = 0
    #     while item_hash in self.items:
    #         item_hash = self.items[item_hash].previous_hash
    #         height += 1
    #     return height, item_hash

    def is_child_of(self, item_hash, possible_child_hash):
        if self.get_last(item_hash) != self.get_last(possible_child_hash):
            return None
        while True:
            if possible_child_hash == item_hash:
                return True
            if possible_child_hash not in self.items:
                return False
            possible_child_hash = self.items[possible_child_hash].previous_hash
    #=============

    def get_delta(self, item):
        class delta:
            def __init__(self, _item):
                self.head = _item.hash
                self.tail = _item.previous_hash
                self.work = _item.work

            def __add__(self, other):
                assert self.tail == other.head
                res = self.__class__(self.head)
                res.tail = other.tail
                res.work = self.work + other.work
                return res

        return delta(item)
    
    def get_delta_none(self, item):
        class delta:
            def __init__(self, hash):
                self.head = hash
                self.tail = hash
                self.work = 0

            def __add__(self, other):
                assert self.tail == other.head
                res = self.__class__(self.head)
                res.tail = other.tail
                res.work = self.work + other.work
                return res

        return delta(item)

    def add(self, item):
        assert not isinstance(item, (int, type(None))) #@
        delta = self.get_delta(item)    #@
        
        if delta.head in self.items:
            raise ValueError('item already present')
        
        if delta.head in self.tails:
            heads = self.tails.pop(delta.head)
        else:
            heads = set([delta.head])
        
        if delta.tail in self.heads:
            tail = self.heads.pop(delta.tail)
        else:
            tail = self.get_last(delta.tail)
        
        self.items[delta.head] = item
        self.reverse.setdefault(delta.tail, set()).add(delta.head)
        
        self.tails.setdefault(tail, set()).update(heads)
        if delta.tail in self.tails[tail]:
            self.tails[tail].remove(delta.tail)
        
        for head in heads:
            self.heads[head] = tail
        
    
    def remove(self, item_hash):
        assert isinstance(item_hash, (int, type(None)))
        if item_hash not in self.items:
            raise KeyError()
        
        item = self.items[item_hash]
        del item_hash
        
        delta = self.get_delta(item)
        
        children = self.reverse.get(delta.head, set())
        
        if delta.head in self.heads and delta.tail in self.tails:
            tail = self.heads.pop(delta.head)
            self.tails[tail].remove(delta.head)
            if not self.tails[delta.tail]:
                self.tails.pop(delta.tail)
        elif delta.head in self.heads:
            tail = self.heads.pop(delta.head)
            self.tails[tail].remove(delta.head)
            if self.reverse[delta.tail] != set([delta.head]):
                pass # has sibling
            else:
                self.tails[tail].add(delta.tail)
                self.heads[delta.tail] = tail
        elif delta.tail in self.tails and len(self.reverse[delta.tail]) <= 1:
            heads = self.tails.pop(delta.tail)
            for head in heads:
                self.heads[head] = delta.head
            self.tails[delta.head] = set(heads)
            
            #self.remove_special.happened(item)
        elif delta.tail in self.tails and len(self.reverse[delta.tail]) > 1:
            heads = [x for x in self.tails[delta.tail] if self.is_child_of(delta.head, x)]
            self.tails[delta.tail] -= set(heads)
            if not self.tails[delta.tail]:
                self.tails.pop(delta.tail)
            for head in heads:
                self.heads[head] = delta.head
            assert delta.head not in self.tails
            self.tails[delta.head] = set(heads)
            
            #self.remove_special2.happened(item)
        else:
            raise NotImplementedError()
        
        self.items.pop(delta.head)
        self.reverse[delta.tail].remove(delta.head)
        if not self.reverse[delta.tail]:
            self.reverse.pop(delta.tail)


def action(f = None, value = None):
    if not f is None:
        print("Action {0}, with value {1}:".format(f, value))
        getattr(tracker, f)(value)
    print("items: {0}".format(tracker.items))
    print("reverse: {0}".format(tracker.reverse))
    print("tails: {0}".format(tracker.tails))
    print("heads: {0}".format(tracker.heads))
    print("")


items = [Share(i) for i in range(1, 11)]
print(items)
tracker = OkayTracker(items)
action()

action("add", Share(12))

action("add", Share(11))

action("add", Share(13, 2))

action("add", Share(-10, 4))

action("remove", 1)

for item in [Share(i) for i in range(21, 26)]:
    tracker.add(item)
action()

#result for tests:
# [[0]<-[1]: 100, [1]<-[2]: 200, [2]<-[3]: 300, [3]<-[4]: 400, [4]<-[5]: 500, [5]<-[6]: 600, [6]<-[7]: 700, [7]<-[8]: 800, [8]<-[9]: 900, [9]<-[10]: 1000]
# items: {1: [0]<-[1]: 100, 2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000}
# reverse: {0: set([1]), 1: set([2]), 2: set([3]), 3: set([4]), 4: set([5]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10])}
# tails: {0: set([10])}
# heads: {10: 0}

# Action add, with value [11]<-[12]: 1200:
# items: {1: [0]<-[1]: 100, 2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 12: [11]<-[12]: 1200}
# reverse: {0: set([1]), 1: set([2]), 2: set([3]), 3: set([4]), 4: set([5]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 11: set([12])}
# tails: {0: set([10]), 11: set([12])}
# heads: {10: 0, 12: 11}

# Action add, with value [10]<-[11]: 1100:
# items: {1: [0]<-[1]: 100, 2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 11: [10]<-[11]: 1100, 12: [11]<-[12]: 1200}
# reverse: {0: set([1]), 1: set([2]), 2: set([3]), 3: set([4]), 4: set([5]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 10: set([11]), 11: set([12])}
# tails: {0: set([12])}
# heads: {12: 0}

# Action add, with value [2]<-[13]: 1300:
# items: {1: [0]<-[1]: 100, 2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 11: [10]<-[11]: 1100, 12: [11]<-[12]: 1200, 13: [2]<-[13]: 1300}
# reverse: {0: set([1]), 1: set([2]), 2: set([3, 13]), 3: set([4]), 4: set([5]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 10: set([11]), 11: set([12])}
# tails: {0: set([12, 13])}
# heads: {12: 0, 13: 0}

# Action add, with value [4]<-[-10]: -1000:
# items: {1: [0]<-[1]: 100, 2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 11: [10]<-[11]: 1100, 12: [11]<-[12]: 1200, 13: [2]<-[13]: 1300, -10: [4]<-[-10]: -1000}
# reverse: {0: set([1]), 1: set([2]), 2: set([3, 13]), 3: set([4]), 4: set([5, -10]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 10: set([11]), 11: set([12])}
# tails: {0: set([12, 13, -10])}
# heads: {-10: 0, 12: 0, 13: 0}

# Action remove, with value 1:
# items: {2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 11: [10]<-[11]: 1100, 12: [11]<-[12]: 1200, 13: [2]<-[13]: 1300, -10: [4]<-[-10]: -1000}
# reverse: {1: set([2]), 2: set([3, 13]), 3: set([4]), 4: set([5, -10]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 10: set([11]), 11: set([12])}
# tails: {1: set([12, 13, -10])}
# heads: {-10: 1, 12: 1, 13: 1}

# items: {2: [1]<-[2]: 200, 3: [2]<-[3]: 300, 4: [3]<-[4]: 400, 5: [4]<-[5]: 500, 6: [5]<-[6]: 600, 7: [6]<-[7]: 700, 8: [7]<-[8]: 800, 9: [8]<-[9]: 900, 10: [9]<-[10]: 1000, 11: [10]<-[11]: 1100, 12: [11]<-[12]: 1200, 13: [2]<-[13]: 1300, 21: [20]<-[21]: 2100, -10: [4]<-[-10]: -1000, 23: [22]<-[23]: 2300, 24: [23]<-[24]: 2400, 25: [24]<-[25]: 2500, 22: [21]<-[22]: 2200}
# reverse: {1: set([2]), 2: set([3, 13]), 3: set([4]), 4: set([5, -10]), 5: set([6]), 6: set([7]), 7: set([8]), 8: set([9]), 9: set([10]), 10: set([11]), 11: set([12]), 20: set([21]), 21: set([22]), 22: set([23]), 23: set([24]), 24: set([25])}
# tails: {1: set([12, 13, -10]), 20: set([25])}
# heads: {-10: 1, 25: 20, 12: 1, 13: 1}
