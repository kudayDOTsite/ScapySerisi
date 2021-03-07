import sys
import scapy.all as scapy

def PacketHand(pkt):
	if(pkt.haslayer(scapy.Dot11)):
		print(pkt.summary())
	else:
		print("Not an 802.11 Packet!")


iface = sys.argv[1]
pkt_count = int(sys.argv[2])

scapy.sniff(iface = iface, count = pkt_count, prn = PacketHand)

