Harika! Çok heycanlıyım, scapy serisine başlıyoruz. Böylece ilerleyen zamanlarda yeni rojelerim olacak ve kendi wireless araçlarımı kullanacağım. Bir kişinin özel amaçlarında ya da iş için kendi araçlarını kullanması kadar güzel-tatmin edici bir duygu yok!

Scapy hakkında temel bilgü düzeyinizin olduğunu düşünerek tarihçeini geçiyorum. Bu serinin asıl amacı scapy ile wireless testlerinde çokça kullandığımız air****ng serisie ait araçların çalışma mantığını anlamak olacaktır. 

Bir wireless testine yaptığımız ilk iş belkide monitor mode'a aldığımız kart ile dump işlemleri yapmaktır. İlgili SSID'leri tespit etmek ile başlarız. Scapy ile bu işlemi nasıl yapabileceğimizi gösterek başlamak istiyorum. Seri boyunca KALI kullanacağım. Son bir not python ve wireless için ekstra bir bilgi paylaşımında bulunmayacağım. Temel wireless güvenliği ve python programalam bildiğinizi varsayorum.

```sh
┌──(root💀kali)-[/home/sarikamyon]
└─# iwconfig
lo        no wireless extensions.

eth0      no wireless extensions.

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off
          
```

Evet görüldüğü üzere wireless kartı takılı.

```sh
┌──(root💀kali)-[/home/sarikamyon]
└─# scapy                          
INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
                                      
                     aSPY//YASa       
             apyyyyCY//////////YCa       |
            sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
 ayp ayyyyyyySCP//Pp           syY//C    | Version 2.4.4
 AYAsAYYYYYYYY///Ps              cY//S   |
         pCCCCY//p          cSSps y//Y   | https://github.com/secdev/scapy
         SPPPP///a          pP///AC//Y   |
              A//A            cyP////C   | Have fun!
              p///Ac            sC///a   |
              P////YCpc           A//A   | We are in France, we say Skappee.
       scccccp///pSP///p          p//Y   | OK? Merci.
      sY/////////y  caa           S//P   |             -- Sebastien Chabal
       cayCyayP//Ya              pY/Ya   |
        sY/PsY////YCc          aC//Yp 
         sc  sccaCY//PCypaapyCP//YSs  
                  spCPY//////YPSps    
                       ccaacs         
                                       using IPython 7.19.0
>>> 
```
Terminale `scapy` diyerek (sikiipi şeklinde telafuz edilir - sakın dışarda sıkapi demeyin) scapy'nin kabuğuna geçiş yapalım.

Scapy ile büyük ihtimalle daha önecsined DDOS yapan bir araç yazmış olabilirsiniz ya da var olan bir aracın içerisinde scapy'nin kullanldığını görmüşsünüzdür. enim ilk zamanlar aklıma hep şöyle bir soru gelirdi, diyelimki birden fazla ağ adaptörüm var scapy hangisi ile çıkış yapacağını nerden biliyor? Biz şuanda eth0 ve wlan0 ağ adaptörlerine sahibiz, scapy büyük ihtimalle eth0 üzerinden işlem yapacaktır ancak ben wlan0 üzerinden işlem yapmasını istiyorum. Bu sayede monitor mode'a geçiş yaptığımda sadece ilgili paketleri görebileceğim. İşte bunun cevabı scapy'nin konfigürasyonlarında saklı. Hemen bakalım.

```sh
>>> conf
ASN1_default_codec = <ASN1Codec BER[1]>
AS_resolver = <scapy.as_resolvers.AS_resolver_multi object at 0x7f264b35b790>
BTsocket   = <BluetoothRFCommSocket: read/write packets on a connected L2CAP...
L2listen   = <L2ListenSocket: read packets at layer 2 using Linux PF_PACKET ...
L2socket   = <L2Socket: read/write packets at layer 2 using Linux PF_PACKET ...
L3socket   = <L3PacketSocket: read/write packets at layer 3 using Linux PF_P...
L3socket6  = functools.partial(<L3PacketSocket: read/write packets at layer ...
USBsocket  = None
auto_crop_tables = True
auto_fragment = True
bufsize    = 65536
cache_iflist = {}
checkIPID  = False
checkIPaddr = True
checkIPinIP = True
checkIPsrc = True
check_TCPerror_seqack = False
color_theme = <DefaultTheme>
commands   = IPID_count : Identify IP id values classes in a list of packets...
contribs   = {}
crypto_valid = True
crypto_valid_advanced = True
debug_dissector = False
debug_match = False
debug_tls  = False
default_l2 = <class 'scapy.packet.Raw'>
dot15d4_protocol = None
emph       = <Emphasize []>
except_filter = ''
extensions_paths = '.'
fancy_prompt = True
filter     = ''
geoip_city = None
histfile   = '/root/.scapy_history'
iface      = 'eth0'
interactive = True
interactive_shell = ''
ipv6_enabled = True
l2types    = 0x0 -> Loopback (Loopback) 0x1 <- Dot3 (802.3) 0x1 <-> Ether (E...
l3types    = 0x3 -> IP (IP) 0x800 <-> IP (IP) 0x806 <-> ARP (ARP) 0x86dd <->...
layers     = Packet : <member 'name' of 'Packet' objects> NoPayload : <membe...
load_layers = ['bluetooth', 'bluetooth4LE', 'dhcp', 'dhcp6', 'dns', 'dot11',...
logLevel   = 20
loopback_name = 'lo'
mib        = <MIB - 343 elements>
min_pkt_size = 60
neighbor   = Ether -> LLC Dot3 -> LLC Dot3 -> SNAP Ether -> Dot1Q Ether -> A...
netcache   = arp_cache: 0 valid items. Timeout=120s in6_neighbor: 0 valid it...
noenum     = <Resolve []>
padding    = 1
padding_layer = <class 'scapy.packet.Padding'>
prog       = display = 'display' dot = 'dot' hexedit = 'hexer' ifconfig = 'i...
promisc    = True
prompt     = '>>> '
raise_no_dst_mac = False
raw_layer  = <class 'scapy.packet.Raw'>
raw_summary = False
recv_poll_rate = 0.05
resolve    = <Resolve []>
route      = Network Netmask Gateway Iface Output IP Metric 0.0.0.0 0.0.0.0 ...
route6     = Destination Next Hop Iface Src candidates Metric ::1/128 :: lo ...
session    = ''
sniff_promisc = 1
stats_classic_protocols = [<class 'scapy.layers.inet.TCP'>, <class 'scapy.la...
stats_dot11_protocols = [<class 'scapy.layers.inet.TCP'>, <class 'scapy.laye...
stealth    = 'not implemented'
temp_files = []
teredoPrefix = '2001::'
teredoServerPort = 3544
use_bpf    = False
use_npcap  = False
use_pcap   = False
use_pypy   = False
verb       = 2
version    = '2.4.4'
warning_threshold = 5
wepkey     = ''
>>> 

```
Harika bütün conf bilgilerini elde ettik. Şimdi aradığımız conf'a bakalım.
```sh
>>> conf.iface
'eth0'

```

Evet tam da düşündüğümüz gibi! Wireless testlerine başlamak için bu değişikliği yapmamız gerekectir. Kartımızı monitor mode'a alalım ve `conf.iface` ifaesini güncelleyelim. Ayrı bir terminal ekranında gerekli işlemleri yapalım.

```sh
┌──(sarikamyon㉿kali)-[~]
└─$ sudo su
[sudo] password for sarikamyon: 
┌──(root💀kali)-[/home/sarikamyon]
└─# airmon-ng                         

PHY	Interface	Driver		Chipset

phy0	wlan0		rt2800usb	Ralink Technology, Corp. RT5372

                                                                                                                                                                                                                                              
┌──(root💀kali)-[/home/sarikamyon]
└─# airmon-ng check kill 

Killing these processes:

    PID Name
   1111 wpa_supplicant

                                                                                                                                                                                                                                              
┌──(root💀kali)-[/home/sarikamyon]
└─# airmon-ng start wlan0


PHY	Interface	Driver		Chipset

phy0	wlan0		rt2800usb	Ralink Technology, Corp. RT5372
		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)


┌──(root💀kali)-[/home/sarikamyon]
└─# iwconfig                                                                                                                                                                                                                            237 ⨯
lo        no wireless extensions.

eth0      no wireless extensions.

wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off

```

Harika şimdi güncellememizi yapalım.
```sh
>>> conf.iface = 'wlan0mon'
>>> 
>>> 
>>> conf.iface
'wlan0mon'
```
Artık ilk sniffimizi yapabiliriz.

```sh
>>> Pkts = sniff(count=1)
>>> 
>>> Pkts
<Sniffed: TCP:0 UDP:0 ICMP:0 Other:1>
>>> 
>>> Pkts.summary()
RadioTap / 802.11 Control Block Ack Request 5c:63:bf:56:81:bc (TA) > 7c:23:02:d0:f0:3a (RA) / Raw
>>> 

```

Harika değil mi? Ne kadar da kolay! Hadi 10 adet sniff yapalım.

```sh
>>> pkts =sniff(10)
>>> 
>>> pkts.nsummary()
0000 RadioTap / 802.11 Management Beacon 5c:63:bf:56:81:bc (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='TurkTelekom_T3AA9' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltERP / Dot11Elt / Dot11EltRSN / Dot11EltRates / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltMicrosoftWPA / Dot11EltVendorSpecific / Dot11Elt
0001 RadioTap / 802.11 Management Beacon 5c:63:bf:56:81:bc (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='TurkTelekom_T3AA9' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltERP / Dot11Elt / Dot11EltRSN / Dot11EltRates / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltMicrosoftWPA / Dot11EltVendorSpecific / Dot11Elt
0002 RadioTap / 802.11 Management Beacon b4:1c:30:77:e9:e4 (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='Superbox_Wifi_4619' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltCountry / Dot11EltERP / Dot11EltRates / Dot11Elt / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltRSN / Dot11EltVendorSpecific
0003 RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 1c:cc:d6:76:de:c9 (RA)
0004 RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 56:62:82:44:9f:7d (RA)
0005 RadioTap / 802.11 Management Beacon 5c:63:bf:0e:f3:90 (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='TurkTelekom_T478D' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltERP / Dot11Elt / Dot11EltRSN / Dot11EltRates / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltMicrosoftWPA / Dot11EltVendorSpecific / Dot11Elt
0006 RadioTap / 802.11 Control Ack 00:00:00:00:00:00 (TA) > 56:62:82:44:9f:7d (RA)
0007 RadioTap / 802.11 Management Beacon 5c:63:bf:56:81:bc (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='TurkTelekom_T3AA9' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltERP / Dot11Elt / Dot11EltRSN / Dot11EltRates / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltMicrosoftWPA / Dot11EltVendorSpecific / Dot11Elt
0008 RadioTap / 802.11 Management Beacon b4:1c:30:77:e9:e4 (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='Superbox_Wifi_4619' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltCountry / Dot11EltERP / Dot11EltRates / Dot11Elt / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltRSN / Dot11EltVendorSpecific
0009 RadioTap / 802.11 Management Beacon b4:1c:30:77:e9:e4 (TA=SA) > ff:ff:ff:ff:ff:ff (RA=DA) / Dot11Beacon / SSID='Superbox_Wifi_4619' / Dot11EltRates / Dot11EltDSSSet / Dot11Elt / Dot11EltCountry / Dot11EltERP / Dot11EltRates / Dot11Elt / Dot11EltHTCapabilities / Dot11Elt / Dot11Elt / Dot11Elt / Dot11EltVendorSpecific / Dot11EltVendorSpecific / Dot11EltRSN / Dot11EltVendorSpecific
>>> 
```

Harika sniff işleminde bazı SSID'leri yakaladık. Bir sonraki yazıda bunar bir python projesi ile nasıl yapabileceğimizi göreceğiz.

