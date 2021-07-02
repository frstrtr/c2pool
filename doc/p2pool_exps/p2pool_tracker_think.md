
OkayTracker.think():
#=====================

#Цикл проходит по всем хэшам шар, которые есть в heads и которых нет в verified.heads
for head in set(self.heads) - set(self.verified.heads):

# Разобрано, но в виде кода
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
for bad in bads:
    assert bad not in self.verified.items
    #assert bad in self.heads
    bad_share = self.items[bad]
    if bad_share.peer_addr is not None:
        bad_peer_addresses.add(bad_share.peer_addr)
    if p2pool.DEBUG:
        print "BAD", bad
    try:
        self.remove(bad)
    except NotImplementedError:
        pass
# ============================================

Перебор @head in verified.heads:
    @head_height, @last_hash = verified.get_height_and_last(@head)
    @last_height, @last_last_hash = get_height_and_last(@last_hash)

    #net.CHAIN_LENGTH = 24*60*60//10
    @want = max(net.CHAIN_LENGTH - @head_height, 0)
    
    # @can
    if last_last_hash is not None:
        @can = max(last_height - 1 - self.net.CHAIN_LENGTH, 0)
    else:
        @can = last_height

    @get = min(@want, @can)

    #(?) для кэширования verify
    Перебор @share in get_chain(@last_hash, @get)
        Для каждой @share вызывается attempt_verify(@share)
            если хотя бы раз метод вернёт false, то цикл прекращется (вызывает break)
    
    Если (head_height < net.CHAIN_LENGTH) and (@last_last_hash is not None):
        desired.add(
            (
                1) #peer_addr
                    # Берётся список хэшей всех шар, которые считают last_hash своим previous_hash
                    a = list(verified.reverse[last_hash])
                    # Выбирается случайный хэш (элемент) из a
                    b = random.choice(a)
                    (1) = self.items[b].peer_addr
                2) #hash
                    (2) = last_last_hash
                3) #timestamp
                    a = []
                    for x in get_chain(head, min(head_height, 5)):
                        a += [x.timestamp]
                    # выбирается максимальный timestamp в этой цепи.
                    (3) = max(a)
                4) #target
                    a = []
                    for x in get_chain(head, min(head_height, 5)):
                        a += [x.target]
                    # выбирается минимальный target в этой цепи.
                    (4) = min(a)
            )
        )
    
# decide best tree
decorated_tails = [] #состоит из кортежей
for tail_hash in self.verified.tails:
    #Выбираем шару с максимальным work (get_work) из всех считающих себя best в форке, где last = tail_hash
    max_get_work = max(self.verified.tails[tail_hash], key=self.verified.get_work)
    #_score - результат метода, который используется для оценки лучшей шары по ключу tail_hash в verified.tails, где лучшая является та, у которой verified.get_work(share) возвращает бОльший результат.
    _score = self.score(max_get_work, block_rel_height_func)
    decorated_tails += (_score, tail_hash)
decorated_tails = sorted(decorated_tails)
    
if decorated_tails: #если список не пуст
    best_tail_score, best_tail = decorated_tails[-1] #best будет считаться с самым большим _score
else: #если список пуст
    best_tail_score, best_tail = (None, None)

# decide best verified head
decorated_heads = []
#Проходимся по хэшам всех шар, считающих себя best в форке, где last = @best_tail
for h in self.verified.tails.get(best_tail, []):
    decorated_heads += [
        ((
        self.verified.get_work(self.verified.get_nth_parent_hash(h, min(5, self.verified.get_height(h)))),
        -self.items[h].should_punish_reason(previous_block, bits, self, known_txs)[0],
        -self.items[h].time_seen,
    ), h)
    ]
decorated_heads = sorted(decorated_heads)

if decorated_heads: #если список не пуст
    best_head_score, best = decorated_heads[-1] #best будет считаться с самым большим _score
else: #если список пуст
    best_head_score, best = (None, None)

#
Если best не None:
    @best_share = self.items[best]

    #вызывается should_punish_reason, которая проверяет, есть ли причины "наказания" для шары.
    # punish = -1, если шара является решением блока.
    # Фактически, метод возвращает punish > 0, если:
    # 1) txs over block weight limit
    # 2) txs over block size limit
    # В таком случае, best шарой становится previous_hash
    punish, punish_reason = best_share.should_punish_reason(previous_block, bits, self, known_txs)
            if punish > 0:
                print 'Punishing share for %r! Jumping from %s to %s!' % (punish_reason, format_hash(best), format_hash(best_share.previous_hash))
                best = best_share.previous_hash

    #классически Форрестер берёт числа из головы и умножает на них; так же тут используется работа с точностью при делении.
    timestamp_cutoff = min(int(time.time()), best_share.timestamp) - 3600
    target_cutoff = int(2**256//(self.net.SHARE_PERIOD*best_tail_score[1] + 1) * 2 + .5) if best_tail_score[1] is not None else 2**256-1
else:
    timestamp_cutoff = int(time.time()) - 24*60*60
    target_cutoff = 2**256-1


# Результат работы think()

result = (
    1) #hash of best share
        (1) @best
    2) #список из (peer_addr, hash)
        [(peer_addr, hash) for peer_addr, hash, ts, targ in desired if ts >= timestamp_cutoff]
        res = []
        for (peer_addr, hash, ts, targ) in @desired:
            if ts >= timestamp_cutoff:
                res += [(peer_addr, hash)]

        (2) @res
    3) 
        (3) decorated_heads
    4) 
        (4) bad_peer_addresses
)

return result