

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
    
    