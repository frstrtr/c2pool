def get_attributedelta_type(attrs): # attrs: {name: func}
    class ProtoAttributeDelta(object):
        __slots__ = ['head', 'tail'] + list(attrs.keys())

        @classmethod
        def get_none(cls, element_id):
            return cls(element_id, element_id, **dict((k, 0) for k in attrs)) #TODO: head and tail = element_id???
        
        @classmethod
        def from_element(cls, item):
            return cls(item.hash, item.previous_hash, **dict((k, v(item)) for k, v in attrs.items()))
        
        @staticmethod
        def get_head(item):
            return item.hash
        
        @staticmethod
        def get_tail(item):
            return item.previous_hash
        
        def __init__(self, head, tail, **kwargs):
            self.head, self.tail = head, tail
            for k, v in kwargs.items():
                setattr(self, k, v)
        
        def __add__(self, other):
            assert self.tail == other.head
            return self.__class__(self.head, other.tail, **dict((k, getattr(self, k) + getattr(other, k)) for k in attrs))
        
        def __sub__(self, other):
            if self.head == other.head:
                return self.__class__(other.tail, self.tail, **dict((k, getattr(self, k) - getattr(other, k)) for k in attrs))
            elif self.tail == other.tail:
                return self.__class__(self.head, other.head, **dict((k, getattr(self, k) - getattr(other, k)) for k in attrs))
            else:
                raise AssertionError()
        
        def __repr__(self):
            return '%s(%r, %r%s)' % (self.__class__, self.head, self.tail, ''.join(', %s=%r' % (k, getattr(self, k)) for k in attrs))
    ProtoAttributeDelta.attrs = attrs
    return ProtoAttributeDelta

AttributeDelta = get_attributedelta_type(dict(
    height=lambda item: 1,
))

AttributeDelta2 = get_attributedelta_type(dict(
    height=lambda item: 1,
))

class TestShare(object):
    

    def __init__(self, _hash, _prev, _data):
        self.hash = _hash
        self.previous_hash = _prev
        self.data = _data

test_share = TestShare(1337, 7331, 1234)
test_share2 = TestShare(7331, 4444, 4321)

delta_type = AttributeDelta
delta = delta_type.from_element(test_share)
print(delta.tail)
print(delta.__slots__)
delta_type2 = AttributeDelta2
delta2 = delta_type2.from_element(test_share2)

delta += delta2
print(delta.head)
print(delta.tail)
print(delta.height)
print(delta.__slots__)