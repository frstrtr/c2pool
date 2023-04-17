import random
import sys
import time

import deferral
import variable

from twisted.internet import defer, reactor
from twisted.python import log

class Node:

    def __init__(self):
        self.desired_var = variable.Variable([])

    def start(self):
        @apply
        @defer.inlineCallbacks
        def download_shares():
            while True:
                print("0!")
                
                def satisfies_f(val):
                    print('SATISFIES: {0}'.format(val))
                    return len(val) != 0
                
                desired = yield self.desired_var.get_when_satisfies(satisfies_f)
                print("1!")
                try:
                    #yield
                    pass
                except:
                    print("EXCEPT")
                    continue

                yield deferral.sleep(1)
                print("="*10)


node = Node()
node.start()

temp = []

def timerF(i):
    global temp
    print('TIMER_F[{0}]: {1}'.format(i, int(time.time())))
    if i % 2:
        temp += [i]
        node.desired_var.set(temp)
    else:
        node.desired_var.set([])

print('START: {0}'.format(int(time.time())))
for i in range(1, 12):
    timeout_delayed = reactor.callLater(3 + 3*i, timerF, i)
    

reactor.run()