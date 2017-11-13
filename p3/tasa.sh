#!/bin/bash
#Archivo que analiza la tasa o ancho de banda de la traza que recibe como argumento en bits

if ! [ -e tasas.tmp ]
then
tshark -r $1 -qz io,stat,1,"SUM(frame.len)frame.len" > tasas.tmp
fi

sed "1,12d" tasas.tmp |awk '{print $6*8}'
