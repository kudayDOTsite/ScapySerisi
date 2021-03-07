Geçen yazımızfa scapy ekranı üzerinden sniff işlemi gerçekleştirdik şimdi bunu bir python projesi olarak yapalım. Aşağıdaki kodu incelediğinide ne yaptığımızı anlayacaksınızıdır.

```py
  GNU nano 5.3                                                                                                    sniffPacket.py                                                                                                              
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
```

Şimdi çalıştıralım. İlk olarak eth0 ile çalıştıracağım.

```sh
                                                                                                                                                                                                                                              
┌──(root💀kali)-[/home/sarikamyon/Desktop/oswp/ScapySerisi]
└─# python3 sniffPacket.py eth0 10
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
Not an 802.11 Packet!
                           
```

Görüldüğü gibi hiç DOT11 yani 8021.11 paketlerine rastlamadık. Ancak monitor mode'da olan wlan0mon arayüzü ile bu işlemi yaparsak...

```py
┌──(root💀kali)-[/home/sarikamyon/Desktop/oswp/ScapySerisi]
└─# python3 sniffPacket.py wlan0mon 10
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 16:fb:67:f3:d0:3f (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 00:17:c4:7d:c8:dc (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 56:62:82:44:9f:7d (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 56:62:82:44:9f:7d (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > fc:4a:e9:91:08:c2 (RA)
RadioTap / 802.11 Management Probe Request 22:b9:a5:6a:14:35 (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11ProbeReq / SSID='' / Dot11EltRates / Dot11EltRates / Dot11EltHTCapabilities
RadioTap / 802.11 Control Block Ack Request 74:da:88:23:1e:ba (TA) > 48:e2:44:60:bf:e3 (RA) / Raw
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 18:48:59:13:59:c6 (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > fc:4a:e9:91:08:c2 (RA)
RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 00:17:c4:7d:c8:dc (RA)

```

Görüldüğü üzere başarılı bir şekilde sniff edebildik.
