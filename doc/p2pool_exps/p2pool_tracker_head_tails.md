Tracker.add(item : hash):
    1. Берется дельта для item:
                     (head       tail                work       min_work     )
            @delta = (item.hash, item.previous_hash, item.work, item.min_work)
    
    (2). Проверка на то, не содержится ли item в трекере (self.items).
            Если содержится, то вызывается raise

    3. 
        Если delta.head содержится в self.tails:
            @heads = self.tails.pop(delta.head)
        else:
            @heads = {delta.head} #set
    
    4.
        Если delta.tail не содержится в self.heads:
            @tail = self.heads.pop(delta.tail)
        else:
            @tail = self.get_last(delta.tail)
    
    (5). item добавляется в self.items:
            self.items[delta.head] = item

    6. В self.reverse[delta.tail] добавляется delta.head:
            self.reverse.setdefault(delta.tail, set()).add(delta.head)

    7. В self.tails[tail] добавляется heads:
            self.tails.setdefault(tail, set()).update(heads)

    8. Проверка
        if delta.tail in self.tails[tail]:
            self.tails[tail].remove(delta.tail)
        
    9. Для всех элементов в @heads:
            self.heads[head] = tail
