#!/bin/bash
#Generador de graficas que recibe como argumentos:
#       -Titulo de la grafica
#       -Nombre del eje X
#       -Nombre del eje Y
#       -Nombre del archivo de entrada
#       -Nombre del archivo de salida
#	-Nombre de la linea

if [ -s $4 ]
then
	echo "Generando grafica $1"
        gnuplot -persist -e "set title \"$1\"; set xlabel \"$2\"; set ylabel \"$3\"; set logscale x; set format x \"%.1e\";" -e "set term jpeg; set output \"$5\"; plot \"$4\" using 1:2 title \"$6\" with lines;"

else
        echo
        echo "El archivo para generar la grafica "$1" esta vacio o no existe, no se puede generar grafica"

fi
