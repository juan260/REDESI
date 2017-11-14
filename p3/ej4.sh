#!/bin/bash
# Recibe como argumento el nombre de una traza y devuelve los anchos de banda en un archivo 
# que recibe como segundo argumento
echo
echo "Calculo de los anchos de banda"

./tasa.sh $1 | awk '{printf("%d\t\t%d\n", NR, $1);}' > $2
#./tasa.sh traza.pcap | awk 'BEGIN{printf("Intervalo\tAncho\n");} {printf("%d\t\t%d\n", NR, $1);}'


