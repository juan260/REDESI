#!/bin/bash

#MAC origen
if ! [ -e macsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.src == 00:11:88:cc:33:21' > macsrcfile.tmp

fi

./ecdf.sh macsrcfile.tmp > graficamacsrc.tmp
./grafica.sh 

#MAC destino
if ! [ -e macdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.dst == 00:11:88:cc:33:21' > macdstfile.tmp

fi

#./ecdf.sh macdstfile.tmp > graficamacdst.tmp

#HTTP origen
if ! [ -e httpsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.srcport == 80' > httpsrcfile.tmp

fi

#./ecdf.sh httpsrcfile.tmp > graficahttpsrc.tmp

#HTTP destino
if ! [ -e httpdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.dstport == 80' > httpdstfile.tmp

fi


#./ecdf.sh httpdstfile.tmp > graficahttpdst.tmp

#DNS origen
if ! [ -e dnssrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.srcport == 53' > dnssrcfile.tmp

fi

#./ecdf.sh dnssrcfile.tmp > graficadnssrc.tmp

#DNS destino
if ! [ -e dnsdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.dstport == 53' > dnsdstfile.tmp

fi

#./ecdf.sh dnsdstfile.tmp > graficadnsdst.tmp

