# pktanalyzer

Network Packet Analyzer. Parse Ethernet, IPv4, TCP and UDP packets and extract header  
information from the packets.

## Usage

To compile:
```shell
$ cd pktanalyzer
$ javac *.java
```

To run:
```shell
$ java pktanalyzer ../pkt/tcp2a.bin
```

## Output

```shell
$ java pktanalyzer ../pkt/udp2a.bin
ETHER: ----- Ether Header -----
ETHER:
ETHER: Packet size = 82 bytes
ETHER: Destination = 00:15:5d:0a:23:0c,
ETHER: Source      = 00:15:5d:0a:23:07,
ETHER: Ethertype = 0800 (IP)
ETHER:
IP: ----- IP Header -----
IP:                      
IP: Version = 4
IP: Header length = 20 bytes
IP: Differentiated Services Code Point: 0x00
IP: Explicit Congestion Notification = 0b00
IP:       0b00 = Non ECN-Capable Transport
IP: Total length = 68 bytes
IP: Identification = 44312
IP: Flags = 0x02
IP:       .1.. .... = do not fragment
IP:       ..0. .... = last fragment
IP: Fragment offset = 0 bytes
IP: Time to live = 64 seconds/hops
IP: Protocol = 17 (UDP)
IP: Header checksum = 0x0ed5
IP: Source address = 172.20.193.253
IP: Destination address = 192.168.80.1
IP: No options
IP:
UDP: ----- UDP Header -----
UDP:                       
UDP: Source port = 55694
UDP: Destination port = 53
UDP: Length = 48
UDP: Checksum = 0x7efd
UDP:                       
UDP: Data: (first 64 bytes)
UDP: e296 0100 0001 0000 0000 0001 0377 7777    '.............www'
UDP: 0372 6974 0365 6475 0000 0100 0100 0029    '.rit.edu.......)'
UDP: 0200 0000 0000 0000                        '................'
```

```shell
$ java pktanalyzer ../pkt/tcp2a.bin
ETHER: ----- Ether Header -----
ETHER:
ETHER: Packet size = 378 bytes
ETHER: Destination = 00:15:5d:0a:23:0c,
ETHER: Source      = 00:15:5d:0a:23:07,
ETHER: Ethertype = 0800 (IP)
ETHER:
IP: ----- IP Header -----
IP:                      
IP: Version = 4
IP: Header length = 20 bytes
IP: Differentiated Services Code Point: 0x00
IP: Explicit Congestion Notification = 0b00
IP:       0b00 = Non ECN-Capable Transport
IP: Total length = 348 bytes
IP: Identification = 59641
IP: Flags = 0x02
IP:       .1.. .... = do not fragment
IP:       ..0. .... = last fragment
IP: Fragment offset = 0 bytes
IP: Time to live = 64 seconds/hops
IP: Protocol = 6 (TCP)
IP: Header checksum = 0x63bd
IP: Source address = 172.20.193.253
IP: Destination address = 204.2.178.208
IP: No options
IP:
TCP: ----- TCP Header -----
TCP:                       
TCP: Source port = 44074
TCP: Destination port = 80
TCP: Sequence number = 1768138820
TCP: Acknowledgement number = 4178919989
TCP: Data offset = 8 bytes
TCP: Header Length = 32 bytes
TCP: Flags = 0x18
TCP:       ..0. .... = No Urgent pointer
TCP:       ...1 .... = Acknowledgement
TCP:       .... 1... = Push
TCP:       .... .0.. = No reset
TCP:       .... ..0. = No syn
TCP:       .... ...0 = No fin
TCP: Window = 279
TCP: Checksum = 0xee33
TCP: Urgent pointer = 0
TCP: Options present
TCP:                       
TCP: Data: (first 64 bytes)
TCP: 4745 5420 2f73 7563 6365 7373 2e74 7874    'GET./success.txt'
TCP: 2048 5454 502f 312e 310d 0a48 6f73 743a    '.HTTP/1.1..Host:'
TCP: 2064 6574 6563 7470 6f72 7461 6c2e 6669    '.detectportal.fi'
TCP: 7265 666f 782e 636f 6d0d 0a55 7365 722d    'refox.com..User-'
```