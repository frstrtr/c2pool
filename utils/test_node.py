from twisted.internet import reactor
from twisted.internet.protocol import ClientCreator
from twisted.internet import protocol
from twisted.python import log

import hashlib
import struct

command = b"version"
payload = b"1111"
prefix = b"\01\02\03\04"

class Protocol(protocol.Protocol):
    def __init__(self):
        global prefix
        self.prefix = prefix
        print(self.prefix)

    def sendPacket(self, command, payload):
        if len(command) >= 12:
            raise ValueError('command too long')
        print(self.prefix)
        # data = self.prefix + struct.pack('<12sI', command, len(payload)) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload
        data = self.prefix 
        print('f:', data)
        data += struct.pack('<12sI', command, len(payload))
        print('f:', data)
        data += hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] 
        print('f:', data)
        data += payload
        print('f:', data)
        self.transport.write(data)
        

def gotProtocol(p):
    global command, payload
    p.sendPacket(command, payload)
    # reactor.callLater(1, p.sendMessage, "This is sent in a second")
    # reactor.callLater(2, p.transport.loseConnection)

creator = ClientCreator(reactor, Protocol)
d = creator.connectTCP("localhost", 5555)
d.addCallback(gotProtocol)
reactor.run()