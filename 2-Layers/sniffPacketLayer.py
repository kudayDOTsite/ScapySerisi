import sys
import scapy.all as scapy

def PacketLayer(pkt):
	if(pkt.haslayer(scapy.Dot11)):
		print("Packet Summary:")
		print(pkt.summary())
		print()
		print("Packet Layers Name:")
		while(1):
			if(type(pkt) != scapy.scapy.packet.NoPayload):
				print(pkt.name)
				pkt = pkt.payload
			else:
				break
	else:
		print("Not an 802.11 Packet!")


iface = sys.argv[1]

scapy.sniff(iface = iface, count = 1, prn = PacketLayer)
