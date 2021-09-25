import itertools
from twisted.internet import defer, reactor
from twisted.web.client import getPage
from twisted.internet.task import deferLater
from twisted.python import failure, log
import treq

class Event(object):
    def __init__(self):
        self.observers = {}
        self.id_generator = itertools.count()
        self._once = None
        self.times = 0
    
    def run_and_watch(self, func):
        func()
        return self.watch(func)

    def watch(self, func):
        id = next(self.id_generator)
        self.observers[id] = func
        return id
    def unwatch(self, id):
        self.observers.pop(id)
    
    @property
    def once(self):
        res = self._once
        if res is None:
            res = self._once = Event()
        return res
    
    def happened(self, *event):
        self.times += 1
        
        once, self._once = self._once, None
        
        for id, func in sorted(self.observers.items()):
            try:
                func(*event)
            except:
                log.err(None, "Error while processing Event callbacks:")
        
        if once is not None:
            once.happened(*event)
    
    def get_deferred(self, timeout=None):
        once = self.once
        df = defer.Deferred()
        id1 = once.watch(lambda *event: df.callback(event))
        return df


def sleep(secs):
    return deferLater(reactor, secs, lambda: None)

def listCallback(results):
    print("1: {0}".format(len(results)))
    print(results)
    reactor.stop()

def finish(ign):
    reactor.stop()

def test():
    e = Event()
    e.watch(lambda i: print("{0} E!".format(i)))
    flag = e.get_deferred()
    
    @defer.inlineCallbacks
    def d1():
        res = treq.get('http://google.com')
        e.happened(1337)
        yield res

    dl = defer.DeferredList([d1(), flag, sleep(15)], fireOnOneCallback=False)
    dl.addCallback(listCallback)
    # dl.addCallback(finish)

test()
reactor.run()