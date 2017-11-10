#!/bin/bash
# Script que muestra el porcentaje de bytes ip y no ip, y dentro de
# los que sean ip los udp, tcp u otros (ip es ethernet = 0x0800
# o ethernet de tipo vlan (0x8100) con tipo vlan ip (0x0800)

#Inicializacion de MACROS
STDPREC=4


tshark -r traza.pcap -T fields -e ip.proto -e ip.dst -e ip.src -e tcp.dstport -e tcp.srcport -e udp.dstport -e udp.srcport -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > ethfile

#tshark -r traza.pcap -T fields -e eth.type -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) and
#                                                ip.proto == 0x06' > tcpfile

#tshark -r traza.pcap -T fields -e eth.type -Y '(eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)) 
#                                               and ip.proto == 0x11' > udpfile

tshark -r traza.pcap -T fields -e eth.type  > allfile

echo "Aqui vamos 1"
#Contamos el tamaño total de la traza, y el numero de tramas ethernet
nlines=$(wc -l < allfile)
ethlines=$(wc -l < ethfile)

#Ahora contamos los udp's y tcp's, guardamos el resultado en un string
results=$(awk 'BEGIN{udp=0;tcp=0;} 
        {if ($1 == 6) tcp=tcp+1;
         if ($1 == 17) udp=udp+1;}
        END{printf("%d %d", tcp, udp);}' ethfile)

#Parseamos el string resultado recortando
#(cut -f <campo que te interesa> -d <separador, que en este caso es el ' ' y
#   que para que shell no crea que es un espacio lo precedemos de \)

tcplines=$(echo $results | cut -f 1 -d \ )
udplines=$(echo $results | cut -f 2 -d \ )

echo "Hola, $LOGNAME"
echo "Porcentaje de paquetes IP: $(echo "$ethlines*100/$nlines" | bc -l | head -c $((3+STDPREC))) %"
echo "Dentro de estos el $(echo "$tcplines*100/$ethlines" | bc -l| head -c $((3+STDPREC))) % son TCP"
echo "y el $(echo "$udplines*100/$ethlines" | bc -l| head -c $((3+STDPREC))) % son UDP"

#Calculemos el top de direcciones Ip por bytes
awk '{printf "%d\t%d\n", $2, $1}' prueba.txt | sort


#Eliminamos archivos temporales
rm -f ethfile  allfile
