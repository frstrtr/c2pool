import math

class FenwickTree:
    def __init__(self, n):
        self.len = 0
        self.tree = [0] * (2**(int(math.ceil(math.log(n, 2)))) + 1)
    
    def update(self, i, val):
        while i < len(self.tree):
            self.tree[i] += val
            i += i & (-i)
    
    def query(self, i):
        res = 0
        while i > 0:
            res += self.tree[i]
            i -= i & (-i)
        return res
    
    def range_query(self, l, r):
        return self.query(r) - self.query(l - 1)
        
tree = FenwickTree(100000)
print(len(tree.tree))