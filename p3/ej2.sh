#!/bin/bash
#Sript que calcula el top 10 de un determinado archivo
#Recibe 3 argumentos: nombre del archivo, nombre del campo calculado y la cadena del tipo de lo 
#impreso en la primera columna (en este ejercicio siempre es o "Puerto" o "Direccion")

echo "Top 10 $2 por numero de paquetes"
sort $1 -n  |cut -f 1|uniq -c|sort -rn|head -n 10|awk -v texto=$3 'BEGIN{printf("\n%s\t\tNumero de paquetes\n", texto);} {printf("%s\t\t%s\n",$2, $1);}'
echo
echo "Top 10 $2 por bytes transmitidos"

sort $1 -n |awk '{array[$1]+=$2;keys[$1]=$1;} END{for(i in keys){printf("%s\t%s\n",array[i],i);}}' |sort -rn|head -n 10|awk -v texto=$3 'BEGIN{printf("\n%s\t\tBytes\n", texto);} {printf("%s\t\t%s\n",$2, $1);}'
echo
