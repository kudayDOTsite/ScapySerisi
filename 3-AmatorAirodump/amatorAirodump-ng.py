import sys
from scapy.all import *
SSID = []
def getSSID(pkt):
	if(pkt.haslayer(Dot11Elt)):
		pkt = pkt[Dot11Elt]
		if(pkt.ID == 0):
			if(pkt.info not in SSID):
				SSID.append(pkt.info)
				print(str(pkt.info))

iface = sys.argv[1]
while(1):
	sniff(iface = iface, count = 1, prn = getSSID)
