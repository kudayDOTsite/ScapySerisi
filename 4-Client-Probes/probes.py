import sys
from scapy.all import *

def GetProbe(pkt):
	if(pkt.haslayer(Dot11ProbeReq)):
		print(ls(pkt))
		exit()

iface = sys.argv[1]

while 1:
	sniff(iface = iface, count = 1, prn = GetProbe)

