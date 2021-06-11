def add_dicts_ext(add_func=lambda a, b: a+b, zero=0):
    def add_dicts(*dicts):
        res = {}
        for d in dicts:
            for k, v in d.iteritems():
                res[k] = add_func(res.get(k, zero), v)
        return dict((k, v) for k, v in res.iteritems() if v != zero)
    return add_dicts
add_dicts = add_dicts_ext()

def flatten_linked_list(x):
    while x is not None:
        print(x)
        x, cur = x
        yield cur

# weights1 = {b"1":2}
# weights2 = {b"3":4}
# weights_list1 = add_dicts(weights1, weights2)
weights_list1 = {b"3":4}

weights3 = {b"5":6}
weights4 = {b"7":8}
weights_list2 = add_dicts(weights3, weights4)

weights_list = (weights_list1, weights_list2)

# print(weights_list1)
# print(weights_list2)

add_dicts(*flatten_linked_list(({1:2},None)))

#res = add_dicts(*flatten_linked_list(weights_list))
#print(res)