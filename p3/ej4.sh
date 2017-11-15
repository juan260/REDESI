#!/bin/bash
# Recibe como argumento el nombre de una traza y devuelve los anchos de banda y los grafica
# Los resultados los exporta en dos graficas con nombres
# "graficaTasaEntrada.jpeg" y graficaTasDeSalida.jpeg"
#echo
#echo "Calculo de los anchos de banda"

#Analiza la tasa o ancho de banda de la traza que recibe como argumento en bits

if ! [ -e tasasin.tmp ]
then
tshark -r $1 -qz io,stat,1,"SUM(frame.len)frame.len&&eth.dst==00:11:88:CC:33:21" > tasasin.tmp
fi 

if ! [ -e tasasout.tmp ]
then
tshark -r $1 -qz io,stat,1,"SUM(frame.len)frame.len&&eth.dst==00:11:88:CC:33:21" > tasasout.tmp
fi

sed "1,12d" tasasin.tmp |awk '{print $6*8}'| awk '{printf("%d\t\t%d\n", NR, $1);}' > datostasa.tmp
./grafica.sh "Ancho de banda de salida en cada segundo" "Ancho (bits/seg)" "Segundo" "datostasa.tmp" "graficaTasaDeEntrada.jpeg" "Tasa"

sed "1,12d" tasasout.tmp |awk '{print $6*8}'| awk '{printf("%d\t\t%d\n", NR, $1);}' > datostasa.tmp
./grafica.sh "Ancho de banda de entrada en cada segundo" "Ancho (bits/seg)" "Segundo" "datostasa.tmp" "graficaTasaDeSalida.jpeg" "Tasa"

rm -f datostasa.tmp


