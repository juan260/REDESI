#!/bin/bash
#Generador de graficas que recibe como argumentos:
#	-Titulo de la grafica
#	-Nombre del eje X
#	-Nombre del eje Y
#	-Nombre del archivo de entrada
#	-Nombre del archivo de salida
if [ -s $4 ]
then
echo
echo "El archivo $4 esta vacio, no se puede generar grafica"
cat $4
else
gnuplot -persist -e "set title \"$1\"; set xlabel \"$2\"; set ylabel \"$3\";" -e "set term jpeg; set output \"$5\"; plot \"$4\" using 1:2 with lines;"
fi
