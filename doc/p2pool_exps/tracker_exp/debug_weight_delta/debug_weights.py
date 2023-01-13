
#C2POOL
f_c2pool = open('weights_c2pool.txt', 'r')
c2pool_data = {}
for l in f_c2pool:
    hash, target, att = [int(x, 16) for x in l.split(' ')]
    if hash in c2pool_data and c2pool_data[hash] != (target, att):
        print('c2pool_duplicate!!!')
        print(c2pool_data[hash])
        print((target, att))
        continue
    c2pool_data[hash] = (target, att)
f_c2pool.close()
print(len(c2pool_data))

#P2POOL
f_p2pool = open('weights_p2pool.txt', 'r')
p2pool_data = {}
for l in f_p2pool:
    hash, target, att = [int(x, 16) for x in l.split(' ')]
    if hash in p2pool_data and p2pool_data[hash] != (target, att):
        print('p2pool_duplicate!!!')
        print(p2pool_data[hash])
        print((target, att))
        continue
    p2pool_data[hash] = (target, att)
f_p2pool.close()
print(len(p2pool_data))

#ALGO
print(c2pool_data.items()[0])
print(p2pool_data.items()[0])
# k, v = p2pool_data.items()[0]
# k2, v2 = (k, c2pool_data[k])
# print(k)
# print(k2)
# print(v)
# print(v2)