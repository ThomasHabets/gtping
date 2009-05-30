#!/usr/bin/python
# gtping/gsnsim.py
#
# Simulate a GSN node in that it responds to GTP pings in different ways.
#
import socket, struct, random, time

def getUnpack(fd):
    """getUnpack(fd)

    recvfrom() and unpack gtp packet.
    """
    data, src = fd.recvfrom(1048576)
    src = src[0],src[1]
    print "from %s port %d len %d" % (src[0], src[1], len(data))
    return src, struct.unpack('cchihcc', data)

def loopNormal(fd):
    """loopNormal(fd)

    Be a perfect gentleman and always return exactly one reply
    """
    while True:
        src, (flags,msg,ln,teid,seq,npdu,next) = getUnpack(fd)        
        if ord(msg) != 1:
            continue

        fd.sendto(struct.pack('cchihcc',
                              flags,
                              chr(2),
                              ln,
                              teid,
                              seq,
                              npdu,
                              next),
                  src)

def loopFixed(fd, num = 2):
    """loopFixed(fd, num = 2)

    Always return num duplicates.
    """
    while True:
        src, (flags,msg,ln,teid,seq,npdu,next) = getUnpack(fd)        
        if ord(msg) != 1:
            continue
        for n in range(num):
            fd.sendto(struct.pack('cchihcc',
                                  flags,
                                  chr(2),
                                  ln,
                                  teid,
                                  seq,
                                  npdu,
                                  next),
                      src)

def loopRandom(fd, minnum = 0, maxnum = 2):
    """loopRandom(fd, num = 2)

    Return between minnum and maxnum replies.
    """
    while True:
        src, (flags,msg,ln,teid,seq,npdu,next) = getUnpack(fd)        
        if ord(msg) != 1:
            continue
        for n in range(random.randint(minnum,maxnum)):
            fd.sendto(struct.pack('cchihcc',
                                  flags,
                                  chr(2),
                                  ln,
                                  teid,
                                  seq,
                                  npdu,
                                  next),
                      src)
        
from threading import Thread

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
        src, (flags,msg,ln,teid,seq,npdu,next) = getUnpack(fd)        
        if ord(msg) != 1:
            continue
        packetscheduler.append( (time.time()
                                 + mintime
                                 + random.random() * (maxtime-mintime),
                                 fd, src,
                               struct.pack('cchihcc',
                                           flags,
                                           chr(2),
                                           ln,
                                           teid,
                                           seq,
                                           npdu,
                                           next),
                               )
                              )

def main():
    fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fd.bind( ('', 2123) )
    try:
        #loopNormal(fd)
        #loopDup(fd)
        #loopRandom(fd)
        loopJitter(fd, mintime=0, maxtime=1)
    except KeyboardInterrupt:
        fd.close()

if __name__ == '__main__':
    main()
