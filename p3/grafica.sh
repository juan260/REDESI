#!/bin/bash
#Generador de graficas que recibe como argumentos:
#	-Titulo de la grafica
#	-Nombre del eje X
#	-Nombre del eje Y
#	-Nombre del archivo de entrada
#	-Nombre del archivo de salida
gnuplot -persist -e "set title \"$1\"; set xlabel \"$2\"; set ylabel \"$3\";" -e "set term jpeg; set output \"$5\"; plot \"$4\" using 1:2 with lines;"

