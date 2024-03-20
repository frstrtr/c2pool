from __future__ import print_function

from twisted.internet import task
from twisted.internet.defer import Deferred
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
import time
import sys

class Client(LineReceiver):

    def connectionMade(self):
        self.msg = b'\x83\xe6],\x81\xbfmhversion\x00\x00\x00\x00\x00\x7f\x00\x00\x00\xeeoH\xb7\xe5\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xb0q\xed\xa2\xe8\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\xa8\n\n\x13\xa0\xdeD(\x9f#\xb3oz\x128222e87-c2pool.bit\x01\x00\x00\x00\tc\x9d\x1c*\xad\x84I\xe4\xa8L\xb7\xa7D\x94\x0b\x0e\xc7\x01Q\xa7\xcdZ^\x9d\x18a3Rc\x82\xd2'
        print(time.time())

    def dataReceived(self, data):
        print('message_version: {0}'.format(data))
        self.transport.write(self.msg)
        for i in range(0,len(data)-8):
            if data[i:i+7] == b'version':
                print('PREFIX: {0}, hex: {1}'.format(data[0:i], data[0:i].hex()))
                return
        


class ClientFactory(ClientFactory):
    protocol = Client

    def __init__(self):
        self.done = Deferred()


    def clientConnectionFailed(self, connector, reason):
        print('connection failed:', reason.getErrorMessage())
        self.done.errback(reason)


    def clientConnectionLost(self, connector, reason):
        print('connection lost:', reason.getErrorMessage())
        self.done.callback(None)



assert len(sys.argv) == 2
addr, port = sys.argv[1].split(':')
def main(reactor):
    factory = ClientFactory()
    reactor.connectTCP(addr, int(port), factory)
    return factory.done

if __name__ == '__main__':
    task.react(main)
