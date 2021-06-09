from twisted.internet import defer, reactor
from twisted.python import failure, log
from twisted.trial import unittest
import random

class GenericDeferrer(object):
    '''
    Converts query with identifier/got response interface to deferred interface
    '''
    
    def __init__(self, max_id, func, timeout=5, on_timeout=lambda: None):
        print("Created GenericDeferrer")
        self.max_id = max_id
        self.func = func
        self.timeout = timeout
        self.on_timeout = on_timeout
        self.map = {}
    
    def __call__(self, *args, **kwargs):
        while True:
            id = random.randrange(self.max_id)
            if id not in self.map:
                break
        def cancel(df):
            df, timer = self.map.pop(id)
            timer.cancel()
        try:
            df = defer.Deferred(cancel)
        except TypeError:
            df = defer.Deferred() # handle older versions of Twisted
        def timeout():
            self.map.pop(id)
            df.errback(failure.Failure(defer.TimeoutError('in GenericDeferrer')))
            self.on_timeout()
        timer = reactor.callLater(self.timeout, timeout)
        self.map[id] = df, timer
        self.func(id, *args, **kwargs)
        return df
    
    def got_response(self, id, resp):
        if id not in self.map:
            return
        df, timer = self.map.pop(id)
        timer.cancel()
        df.callback(resp)
    
    def respond_all(self, resp):
        while self.map:
            id, (df, timer) = self.map.popitem()
            timer.cancel()
            df.errback(resp)

def test_send_shahereq(id, hashes, parents, stops):
    print("{0}, {1}, {2}, {3}".format(id, hashes, parents, stops))

def disconnect():
    print("timeout")

get_shares = GenericDeferrer(
        max_id=2**256,
        func=lambda id, hashes, parents, stops: test_send_shahereq(id=id, hashes=hashes, parents=parents, stops=stops),
        timeout=15,
        on_timeout=disconnect,
    )

#======================================
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.


from twisted.internet import reactor, protocol

class Echo(protocol.Protocol):
    """This is just about the simplest possible protocol"""

    def dataReceived(self, data):
        #get_shares.got_response(1, [])
        if not type(self).flag:
            get_shares.got_response(get_shares.map.items[0], [])
            
            type(self).flag = True
        else:
            get_shares(hashes = [0], parents=0, stops=[])
            

Echo.flag = False

def main():
    """This runs the protocol on port 8000"""
    factory = protocol.ServerFactory()
    factory.protocol = Echo
    reactor.listenTCP(8000, factory)
    reactor.run()


# this only runs if the module was *not* imported
if __name__ == "__main__":
    main()
#======================================