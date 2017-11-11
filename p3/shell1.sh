#!/bin/bash
# Script que muestra el porcentaje de bytes ip y no ip, y dentro de
# los que sean ip los udp, tcp u otros (ip es ethernet = 0x0800
# o ethernet de tipo vlan (0x8100) con tipo vlan ip (0x0800)

#Inicializacion de MACROS
STDPREC=4

if ! [ -e ipsrcfile.tmp ]
then
    tshark -r traza.pcap -T fields -e ip.src -e frame.len -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > ipsrcfile.tmp

fi


if ! [ -e ipdstfile.tmp ]
then
    tshark -r traza.pcap -T fields -e ip.dst -e frame.len -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > ipdstfile.tmp

fi


if ! [ -e udpsrcfile.tmp ]
then
    tshark -r traza.pcap -T fields -e udp.srcport -e frame.len -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) and ip.proto == 0x11' > udpsrcfile.tmp

fi


if ! [ -e udpdstfile.tmp ]
then
    tshark -r traza.pcap -T fields -e udp.dstport -e frame.len -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) and ip.proto == 0x11' > udpdstfile.tmp

fi


if ! [ -e tcpsrcfile.tmp ]
then
    tshark -r traza.pcap -T fields -e tcp.srcport -e frame.len -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) and ip.proto == 0x06' > tcpsrcfile.tmp

fi


if ! [ -e tcpdstfile.tmp ]
then
    tshark -r traza.pcap -T fields -e tcp.dstport -e frame.len -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) and ip.proto == 0x06' > tcpdstfile.tmp

fi
if ! [ -e ipfile ] 
then
tshark -r traza.pcap -T fields -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -e frame.len -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > ipfile
fi

if ! [ -e allfile ]
then
tshark -r traza.pcap -T fields -e eth.type  > allfile
fi

./ej1.sh $STDPREC
echo
#Calculemos el top de direcciones Ip por numero de paquetes
echo "Top direcciones IP origen por numero de paquetes:" 
sort ipsrcfile.tmp |uniq -c|sort -rn|head -n 10 |cut -f 1 #awk 'BEGIN{FS="."; printf("\nDireccion\t\tNumero de paquetes\n");} {printf("%d.%d.%d.%d\t%d\n", $2, $3, $4, $5, $1);}'

echo
echo "Top direcciones IP origen por bytes transmitidos:"
#sort ipsrcfile.tmp|awk '{array=[]}{array[$1]+=$2}'|sort -rn|awk 'BEGIN{printf("\nDireccion\t\tBytes\n");} {printf("%d\t%d\n",$2, $1);}'

