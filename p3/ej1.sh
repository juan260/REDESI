#!/bin/bash
STDPREC=$1

#Contamos el tamaño total de la traza, y el numero de tramas ethernet
nlines=$(wc -l < allfile)
ethlines=$(wc -l < ipfile)

#Parseamos el string resultado recortando

tcplines=$(wc -l < tcpsrcfile.tmp)
udplines=$(wc -l < udpsrcfile.tmp)

echo "Hola, $LOGNAME"
echo "Porcentaje de paquetes IP: $(echo "$ethlines*100/$nlines" | bc -l | head -c $((3+STDPREC))) %"
echo "Dentro de estos el $(echo "$tcplines*100/$ethlines" | bc -l| head -c $((3+STDPREC))) % son TCP"
echo "y el $(echo "$udplines*100/$ethlines" | bc -l| head -c $((3+STDPREC))) % son UDP"


