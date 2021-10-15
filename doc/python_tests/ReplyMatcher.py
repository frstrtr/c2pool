import itertools
import random
import sys
import time

from twisted.internet import defer, reactor
from twisted.python import failure, log

def sleep(t):
    d = defer.Deferred(canceller=lambda d_: dc.cancel())
    dc = reactor.callLater(t, d.callback, None)
    return d


def retry(message='Error:', delay=3, max_retries=None, traceback=True):
    '''
    @retry('Error getting block:', 1)
    @defer.inlineCallbacks
    def get_block(hash):
        ...
    '''
    
    def retry2(func):
        @defer.inlineCallbacks
        def f(*args, **kwargs):
            for i in itertools.count():
                try:
                    result = yield func(*args, **kwargs)
                except:
                    if i == max_retries:
                        raise
                    
                    yield sleep(delay)
                else:
                    defer.returnValue(result)
        return f
    return retry2

class ReplyMatcher(object):
    '''
    Converts request/got response interface to deferred interface
    '''
    
    def __init__(self, func, timeout=5):
        self.func = func
        self.timeout = timeout
        self.map = {}
    
    def __call__(self, id):
        if id not in self.map:
            self.func(id)
        df = defer.Deferred()
        def timeout():
            self.map[id].remove((df, timer))
            if not self.map[id]:
                del self.map[id]
            df.errback(failure.Failure(defer.TimeoutError('in ReplyMatcher')))
        timer = reactor.callLater(self.timeout, timeout)
        self.map.setdefault(id, set()).add((df, timer))
        return df
    
    def got_response(self, id, resp):
        if id not in self.map:
            return
        for df, timer in self.map.pop(id):
            df.callback(resp)
            timer.cancel()

# self.get_block = deferral.ReplyMatcher(lambda hash: self.send_getdata(requests=[dict(type='block', hash=hash)]))
# yield deferral.retry('Error while requesting best block header:')(poll_header)()

def f(i):
    time.sleep(4)
    return i*2


def print_result(res):
    print("RESULT: {0}".format(res))
    reactor.stop()

# retry("Error while req:")(get_block)(1234)
@defer.inlineCallbacks
def reactor_main():
    get_block = ReplyMatcher(f, 10)
    t0 = time.time()
    _df = get_block(1234)
    print(_df)
    _df.addCallback(print_result)

    time.sleep(3)
    t1 = time.time()
    print(get_block.got_response(1234, 23))
    t2 = time.time()
    print(round(t1-t0,1))
    print(round(t2-t1, 1))

reactor.callLater(1, reactor_main)
reactor.run()