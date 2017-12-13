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


chmod u+x chmod.sh
./chmod.sh

echo "Archivos generados"
echo
./ej1.sh $STDPREC
echo
#Calculemos el top de direcciones Ip origen
./ej2.sh ipsrcfile.tmp "direcciones IP origen" "Direccion"

#Calculemos el top de direcciones Ip destino
./ej2.sh ipdstfile.tmp "direcciones IP destino" "Direccion"

#Calculemos el top de direcciones TCP origen 
./ej2.sh tcpsrcfile.tmp "puerto TCP origen" "Puerto"

#Calculemos el top de direcciones TCP destino
./ej2.sh tcpdstfile.tmp "puertos TCP destino" "Puerto"

#Calculemos el top de puertos UDP origen
./ej2.sh udpsrcfile.tmp "puertos UDP origen" "Puerto"

#Calculemos el top de puertos UDP destino
./ej2.sh udpdstfile.tmp "puertos UDP destino" "Puerto"

echo "Ej3"
./ej3.sh

echo
echo "Ej4"
#Calculemos las tasas
./ej4.sh traza.pcap anchos.txt

echo 
echo "Ej5"
#Calculemos el tiempo entre paquetes
./ej5.sh
echo

if ! [ $# == 0 ]
		then
		echo "Modo de conservacion activado, conservando archivos temporales"
else	
	./clean.sh
fi
