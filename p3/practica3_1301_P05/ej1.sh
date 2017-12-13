#!/bin/bash
PREC=$1

#Contamos el tamaño total de la traza, y el numero de tramas ethernet
nlines=$(wc -l < allfile)
ethlines=$(wc -l < ipfile)
tcplines=$(wc -l < tcpsrcfile.tmp)
udplines=$(wc -l < udpsrcfile.tmp)

#Porcentaje de paquetes IP
ipporcien=$(echo "$ethlines*100/$nlines" | bc -l) 
tcpporcien=$(echo "$tcplines*100/$ethlines" | bc -l)
udpporcien=$(echo "$udplines*100/$ethlines" | bc -l)
echo "Hola, $LOGNAME"
echo "Porcentaje de paquetes IP: $(echo $ipporcien |head -c $((3+PREC))) %"
echo "Porcentaje de paquetes NO IP: $(echo "100-$ipporcien" | bc -l|head -c $((3+PREC))) %"
echo "Dentro de estos el $(echo $tcpporcien| head -c $((3+PREC))) % son TCP,"
echo "el $(echo $udpporcien| head -c $((3+PREC))) % son UDP"
echo "y el $(echo "100-$udpporcien-$tcpporcien" | bc -l|head -c $((3+PREC))) % no son ni UDP ni TCP"

