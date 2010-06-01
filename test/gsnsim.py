#!/usr/bin/python
# gtping/gsnsim.py
#
# Simulate a GSN node in that it responds to GTP pings in different ways.
#
import socket, struct, random, time, sys
from threading import Thread

def getPacket(fd):
    data, src = fd.recvfrom(1000000)
    return data, src[:2]

def mkReply(req):
    ver = ord(struct.unpack('c', req[0])[0]) >> 5
    if ver == 1:
        flags,msg,ln,teid,seq,npdu,next = struct.unpack('cchihcc', req)
        if ord(msg) != 1:
            return None

        return struct.pack('cchihcc',
                           flags,
                           chr(2),
                           ln,
                           teid,
                           seq,
                           npdu,
                           next)
    elif ver == 2:
        if len(req) == 8:
            flags,msg,ln,seq,spare = struct.unpack('cchhh', req)
            if ord(msg) != 1:
                return None
            return struct.pack('cchhh',
                               flags,
                               chr(2),
                               ln,
                               seq,
                               spare)
        elif len(req) == 12:
            flags,msg,ln,teid,seq,spare = struct.unpack('cchihh', req)
            if ord(msg) != 1:
                return None
            return struct.pack('cchihh',
                               flags,
                               chr(2),
                               ln,
                               teid,
                               seq,
                               spare)

        else:
            raise "HELL"


def loopNormal(fd):
    """loopNormal(fd)

    Be a perfect gentleman and always return exactly one reply
    """
    while True:
        packet, src = getPacket(fd)
        reply = mkReply(packet)
        fd.sendto(reply, src)


def loopDup(fd, num = 2):
    """loopDup(fd, num = 2)

    Always return num duplicates.
    """
    while True:
        packet, src = getPacket(fd)
        for n in range(num):
            fd.sendto(mkReply(packet), src)

def loopRandom(fd, minnum = 0, maxnum = 2):
    """loopRandom(fd, num = 2)

    Return between minnum and maxnum replies.
    """
    while True:
        packet, src = getPacket(fd)
        for n in range(random.randint(minnum,maxnum)):
            fd.sendto(mkReply(packet), src)
        
packetscheduler = []
class PacketScheduler(Thread):
    def __init__(self):
        Thread.__init__(self)
        pass
    def run(self):
        while True:
            while len(packetscheduler) == 0:
                time.sleep(0.1)
            packetscheduler.sort()
            packetscheduler.reverse()
            t,fd,dst,packet = packetscheduler.pop()
            if t > time.time():
                packetscheduler.append( (t, fd, dst,packet) )
                continue
            fd.sendto(packet, dst)
            
    
def loopJitter(fd, mintime=0, maxtime=1):
    ps = PacketScheduler()
    ps.start()
    while True:
        packet, src = getPacket(fd)
        packetscheduler.append( (time.time()
                                 + mintime
                                 + random.random() * (maxtime-mintime),
                                 fd, src,mkReply(packet)) )

def main():
    fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fd.bind( ('', 2123) )
    try:
        {
            'normal': loopNormal,
            'dup': loopDup,
            'random': loopRandom,
            'jitter': lambda x: loopJitter(x, mintime=0, maxtime=1),
         }.get(dict(zip(range(len(sys.argv)),sys.argv)).get(1, ''),
                         loopNormal)(fd)
    except KeyboardInterrupt:
        fd.close()

if __name__ == '__main__':
    main()
