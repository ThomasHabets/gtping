#!/usr/bin/python
# gtping/gsnsim.py
#
# Simulate a GSN node in that it responds to GTP pings in different ways.
#
import socket, struct, random

def getUnpack(fd):
    """getUnpack(fd)

    recvfrom() and unpack gtp packet.
    """
    data, src = fd.recvfrom(1048576)
    src = src[0],src[1]
    print "from %s port %d" % (src[0],src[1])
    return src, struct.unpack('cchlhcc', data)

def loopNormal(fd):
    """loopNormal(fd)

    Be a perfect gentleman and always return exactly one reply
    """
    while True:
        src, (flags,msg,ln,teid,seq,npdu,next) = getUnpack(fd)        
        if ord(msg) != 1:
            continue

        fd.sendto(struct.pack('cchlhcc',
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
            fd.sendto(struct.pack('cchlhcc',
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
            fd.sendto(struct.pack('cchlhcc',
                                  flags,
                                  chr(2),
                                  ln,
                                  teid,
                                  seq,
                                  npdu,
                                  next),
                      src)
        
        

def main():
    fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fd.bind( ('', 2123) )
    try:
        #loopNormal(fd)
        #loopDup(fd)
        loopRandom(fd)
    except KeyboardInterrupt:
        return

if __name__ == '__main__':
    main()
