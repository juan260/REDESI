#!/bin/bash
#Archivo que analiza la tasa o ancho de banda de la traza que recibe como argumento en bits

if ! [ -e tasasin.tmp ]
then
tshark -r $1 -qz io,stat,1,"SUM(frame.len)frame.len&&eth.dst==00:11:88:CC:33:21" > tasasin.tmp
fi

if ! [ -e tasasout.tmp ]
then
tshark -r $1 -qz io,stat,1,"SUM(frame.len)frame.len&&eth.src==00:11:88:CC:33:21" > tasasout.tmp
fi

sed "1,12d" tasasin.tmp |awk '{print $6*8}'
