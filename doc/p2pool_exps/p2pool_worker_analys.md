1. jsonrpc.py::_handle ?

# Раньше stratum назывался Proxy для jsonrpc coind'a.
#------------------------------

StratumRPCMiningProvider
    Создается и содержится в StratumProtocol в поле self.svc_mining
    StratumRPCMiningProvider содержит поле self.wb, которое получает wb [WorkerBridge] в StratumProtocol, который получает его из StratumServerFactory через поле wb.
        StratumProtocol наследуется от jsonrpc.LineBasedPeer
        |   LineBasedPeer наследуется от twisted.protocols.basic.LineOnlyReceiver
        |-------Имеет self.other = Proxy(self._matcher)
        |-------Имеет self._matcher [в Proxy: self._func], который упаковывает данные для jsonrpc запроса в json в формате: 
                    {
                        'jsonrpc': '2.0',
                        'method': method,
                        'params': params,
                        'id': id,
                    }
        |-------Имеет метод lineReceived(self, line), который вызывается, когда протокол получает jsonrpc запрос (?). Метод вызывает jsonrpc.py::_handle(...), обрабатывающий эту строку.
????????????????????jsonrpc.py::_handle(data, provider, preargs=(), response_handler=None):


            #Example:
            #   Весь файл jsonrpc.py [Proxy, LineBasedPeer] используется для сборки jsonrpc запросов и их передачи/обработки.
            #   В stratum.py есть строка:
            #       self.other.svc_mining.rpc_set_difficulty(bitcoin_data.target_to_difficulty(x['share_target'])*self.wb.net.DUMB_SCRYPT_DIFF).addErrback(lambda err: None)
            #   Где:
            #       other = Proxy
            #       .svc_mining = тому же Proxy, что и в other, только поле Proxy.services = ["mining"]; from svc_<mining>
            #       .rpc_set_difficulty = lambda *params: вызывающая _func = LineBasedPeer._matcher(method = "mining.set_difficulty"["mining" from Proxy.services, set_difficulty from rpc_<set_difficulty>] аргументами *params
            #       
            #   Итог:
            #       вызывается в twisted: sendLine({
            #           'jsonrpc': '2.0',
            #           'method': "mining.set_difficulty",
            #           'params': bitcoin_data.target_to_difficulty(x['share_target'])*self.wb.net.DUMB_SCRYPT_DIFF, #результат вычислений, а не строка
            #           'id': id, #берется из defferal.GenericDeferrer
            #       })

        StratumProtocol Содержится в StratumServerFactory в поле cls: protocol
            StratumServerFactory создается в main.py c аргументов в конструкторе = caching_wb [1], как элемент словаря в конструкторе serverfactory = switchprotocol.FirstByteSwitchFactory(first_byte_factory, default_factory)[2], вместе с web_serverfactory [3]
                [1]caching_wb = worker_interface.py::CachingWorkerBridge(wb)
                    Оболочка для WorkerBridge, имеет те же методы и поля, что и WorkerBridge;
                    Используется для кэширования результатов работы WorkerBridge.get_work(*args) и для избежания повторной аутентификации.
                [2]serverfactory = switchprotocol.FirstByteSwitchFactory,
                    По первому байту потока данных определяет, с каким из двух factory работать. В данном случае:
                        serverfactory = switchprotocol.FirstByteSwitchFactory({'{': stratum.StratumServerFactory(caching_wb)}, web_serverfactory)
                           --- Если первый символ в сообщении = '{', то используется StratumServerFactory, во всех остальных случаях используется web_serverfactory.
                [3]web_serverfactory = server.Site(resource=wrapper)
                    --- для доступа к web статистике (?)
                    

    StratumRPCMiningProvider содержит поле self.other, которое является Proxy, полученное из StratumProtocol при создании StratumRPCMiningProvider