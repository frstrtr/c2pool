get_height_rel_highest - ?
start - ?
---------------------------------------------------------
@ - method
#P2PNode содержит Node, для доступа к словарю peer'ов.
#Node содержит P2PNode , для доступа к:
#   tracker; best_share_var; desired_share; set_best_share; net; handle_header

Node:
    #mining_txs_var - transactions from getblocktemplate
    #mining2_txs_var - transactions sent to miners
    #desired_var - ???
    #cur_share_ver - в set_best_share каждый раз вызывается cur_share_ver = tracker.items[best].VERSION
    0. @__init__
            Инициализация всех _var;
            Создание и инициализация tracker [OkayTracker], а так же наполнение его имеющимися шарами и verified шарами.
    1. @check_and_purge_txs
            Если cur_share_ver < 34 или если besh_share не имеется, то выход из метода; 
            В противном случае:
                if best_share.header['previous_block'] != self.bitcoind_work.value['previous_block']:
                    self.known_txs_var.set({}) #known_txs_var делает пустым, т.е. удаляет известные транзакции.
    2. @set_best_share
            У tracker вызывается think(...), который возвращает:
                (1)best, (2)desired, (3)decorated_heads, (4)bad_peer_addresses, (5)punish
            best_share_var.set((1)best)
            desired_var.set((2)desired)
            Обновляется cur_share_ver = tracker.items[(1)best].VERSION
            Банятся все пиры, что в (4)bad_peer_addresses
    3. @get_current_txouts
            return p2pool_data.get_expected_payouts(self.tracker, self.best_share_var.value, 
                self.bitcoind_work.value['bits'].target, self.bitcoind_work.value['subsidy'], self.net)
                #get_expected_payouts использует:
                    tracker.get_cumulative_weights;
                    tracker.get_height(best_share_hash);
                    donation_script_to_address;
    4. @clean_tracker
            У tracker вызывается think(...), который возвращает:
                (1)best, (2)desired, (3)decorated_heads, (4)bad_peer_addresses, (5)punish
                в clean_tracker используется только (3)decorated_heads.
            Если (3) decorated_heads не пустой, то:
                в цикле for i in range(1000):
                    цикл share_hash, tail in tracker.heads:
                        где проходит проверка на 3 условия, если хотя бы одно true, то в цикле вызывается continue,
                        в противном случае share_hash добавляется в to_remove = set.
                    По окончанию цикла, проходится циклом to_remove:
                        который удаляет шару из tracker.verified и tracker.remove(share_hash)
                ДАЛЬШЕ ????????
    5. @start
            инициализация stop_signal, для остановки процесса при нажатии на ctrl + c
            #BITCOIND WORK:
                Инициализация переменной bitcoind_work = helper.getwork(bincoind)
                Создание и вызов inlineCallback метода @work_poller, которая является лябмдой:
                    метод вызывает каждые 15 секунд, где обновляет значение bitcoind_work
                        bitcoind_work.set((yield helper.getwork(self.bitcoind, self.bitcoind_work.value['use_getblocktemplate'], self.txidcache, self.feecache, self.feefifo, self.known_txs_var.value)))
                    после обновления значения, вызывается check_and_purge_txs()
            #PEER WORK:
                Создается переменная best_block_header [variable.Variable(None)], которая становится полем класса.
                Создается функция handle_header и становится методом класса self.handle_header.
                На событие bitcoind_work.changed, подписывается лямбда и тут же она вызывается:
                    лямбда pool_header вызывает handle_header.
            # BEST SHARE
                ??????

P2PNode:
----p2p.py:
    1. nonce = random (0, 2**64)
    2. client/server factory for message_version, etc...
    3. peers = {}
    4. bans = {(str:address) : (int:end_ban_time)}
    5. @_think:
            Метод вызывается после старта, раз в случайное время = random.expovariate(1/20).
            Если у ноды есть другие подключения и при этом addr_store хранит меньше, чем значение preferred_storage [default = 1000],
                то случайному пиру отправляется сообщение send_getaddrs(count=8).
    6. @got_conn/@lost_conn:
            Методы вызываются, когда получается/отключается подключение.
----node.py
    7. @handle_shares
            Метод для получения самих шар. 
            Вызывается в: download_shares; handle_share_hashes; Protocol.handle_shares.
    8. @handle_share_hashes
            Вызывается в Protocol.handle_version, если best_share_hash in not None.
    9. @handle_get_shares
            Вызывается в Protocol.handle_sharereq.
    10.@handle_bestblock
            Вызывается без обработки в Protocol.handle_bestblock.
    11.@broadcast_share
            Вызывается при изменениии node.best_share_var [# send share when the chain changes to their chain](node.py::P2PNode);
            Вызывается в tracker.verified.added лямбде, которая определена в (node.py::P2PNode::start);
            Вызывается в WorkerBridge.get_work()->called lambda->got_response;

            ??? for ???
    12.@start
            Инициализация клиент и сервер factory's для p2p подключений нод.
            lambda download_shares():
                Запрос и загрузка шар в бесконечном цикле [while True], отправляя пирам Protocol.send_sharereq.
            lambda _ called when node.best_block_header.changed:
                Для всех пиров в self.peers, вызывает метод send_bestblock(header=header);
            Подписывает broadcast_share() на event: node.best_share_var.changed
            lambda _ called when node.tracker.verified.added:
                создаёт метод spread(), вызывает его и вызывает ещё раз через 5 секунд,
                где в spread(), при:
                    node.get_height_rel_highest(share.header['previous_block']) > -5
                    или
                    node.bitcoind_work.value['previous_block'] in [share.header['previous_block'], share.header_hash]
                    вызывается broadcast_share(share.hash)