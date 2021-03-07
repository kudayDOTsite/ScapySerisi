Amacım aslında SSID değerlerini elde etmek. Sadece bu*na odaklanacağım ve şu aşamada aslında scapy'e yeni başladığım için belkide yapmaya çalıştığım şeyleri bir  seferde yapan bazı scapy metotlarını kullanmayacağım. Bu bilinçli bir seçim değildir henüz bilgisiz ve yeni olmamdan kaynaklanmaktadır.

```py
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
```

İşte hepsi bu kadar! DOT11Elt içerisinde ID == 0 aslında SSID demektir. Böyle bir layer tespit ettiğinde bunun info'sunu ekrana bastırıyoruz. Ve bu işlemlerini hepsini uniq bir şekilde gerçekleştiriyoruz. Tabiki yavaş çalışacaktır airodump-ng performansını alabilmek için birden fazla thread ile programı koşturmalıyız ancak bu bir amatör işi!
İşte ekran çıktısı:
```sh
┌──(root💀kali)-[/home/sarikamyon/Desktop/oswp/ScapySerisi]
└─# python3 amatorAirodump-ng.py wlan0mon
b'TurkTelekom_TCD43'
b'TurkTelekom_Z7A93'
b'TURKSAT-KABLONET-E386-2.4G'
b''
b'Superbox_Wifi_4619'
b'TurkTelekom_T478D'
b'ORGUN'
b'TurkTelekom_ZY447'
b'ELIFEDAVETCI'
```
Not: tabi ki burda kanal bilgiside önemli. Sürekli channel değiştirerek bu işlemleri gerçekleştirmek daha fazla SSID'ye ulaşmamızı sağlayacaktır.
