#-*-coding:utf-8-*-
#响应icmp报文
from scapy.all import *

iface = 'wlan0'
attacker_mac = get_if_hwaddr(iface)
print attacker_mac

def send_icmp(pkt):
	if pkt[0][Ether].src != attacker_mac:
		a = IP()
		a.dst = pkt[0][IP].src
		a.src = pkt[0][IP].dst
		b = ICMP()
		b.id = pkt[0][ICMP].id
		b.seq = pkt[0][ICMP].seq
		b.type = 0
		b.code = 0
		c = Raw()
		c.load = pkt[0][Raw]	
		p = a/b/c
		send(p)

pkt = sniff(iface="wlan0",filter="icmp",prn=send_icmp,store=0)