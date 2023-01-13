import p2pool_math

test_data = ((((None, {0:1}), {1:2}), {5:4}), {0:3})
# for x in p2pool_math.flatten_linked_list(test_data):
#     print(x)

a = p2pool_math.add_dicts(*p2pool_math.flatten_linked_list(test_data))

# a = p2pool_math.add_dicts({0:1, 5:4}, {1:2, 0:3})
print(a) # printed: {0: 4, 1: 2, 5: 4}