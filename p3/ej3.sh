#!/bin/bash

#MAC origen
if ! [ -e macsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.src == 00:11:88:cc:33:21' > macsrcfile.tmp

fi

n=$(wc -l < macsrcfile.tmp)


#MAC destino
if ! [ -e macdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.dst == 00:11:88:cc:33:21' > macdstfile.tmp

fi

n1=$(wc -l < macdstfile.tmp)


#HTTP origen
if ! [ -e httpsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.srcport == 80' > httpsrcfile.tmp

fi

n2=$(wc -l < httpsrcfile.tmp)


#HTTP destino
if ! [ -e httpdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.dstport == 80' > httpdstfile.tmp

fi

n3=$(wc -l < httpdstfile.tmp)


#DNS origen
if ! [ -e dnssrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.srcport == 53' > dnssrcfile.tmp

fi

n4=$(wc -l < dnssrcfile.tmp)

#DNS destino
if ! [ -e dnsdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.dstport == 53' > dnsdstfile.tmp

fi

n5=$(wc -l < dnsdstfile.tmp)

