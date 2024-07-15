from twisted.internet import reactor
from twisted.internet.protocol import ClientCreator
from twisted.internet import protocol
from twisted.python import log

import hashlib
import struct
import time

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
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        print("out1: ", hashlib.sha256(payload).hexdigest())
        print("checksum_full: ", checksum.hex())
        print("chesksum_part: ", struct.unpack('<I', checksum[:4]))
        data = self.prefix + struct.pack('<12sI', command, len(payload)) + checksum[:4] + payload
        # data = self.prefix 
        # print('f:', data)
        # data += struct.pack('<12sI', command, len(payload))
        # print('f:', data)
        # data += hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] 
        # print('f:', data)
        # data += payload
        print('f:', data)
        self.transport.write(data)
        

def gotProtocol(p):
    p.sendPacket(b"version", b"11112")
    p.sendPacket(b"test", b"2111111111312312")
    # reactor.stop()
    reactor.callLater(2, reactor.stop)
    # reactor.callLater(1, p.sendMessage, "This is sent in a second")
    # reactor.callLater(2, p.transport.loseConnection)

creator = ClientCreator(reactor, Protocol)
d = creator.connectTCP("localhost", 5555)
d.addCallback(gotProtocol)
reactor.run()