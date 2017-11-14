#!/bin/bash
#Calcula los tiempos de separacion entre paquetes con la frecuencia en la que se dan y los guarda en un €ecdf


if ! [ -e timeipin.tmp ]
then
tshark -r traza.pcap -T fields -e frame.time_delta -Y 'ip.dst==46.69.107.96' > timeipin.tmp
fi


if ! [ -e timeipout.tmp ]
then
tshark -r traza.pcap -T fields -e frame.time_delta -Y 'ip.src==46.69.107.96' > timeipout.tmp
fi


if ! [ -e timeudpin.tmp ]
then
tshark -r traza.pcap -T fields -e frame.time_delta -Y 'udp.dstport==42089' > timeudpin.tmp
fi

if ! [ -e timeudpout.tmp ]
then
tshark -r traza.pcap -T fields -e frame.time_delta -Y 'udp.srcport==42089' > timeudpout.tmp
fi

./ecdf.sh timeipin.tmp > resultadoEj5.tmp

./grafica.sh "ECDF de los tiempos de separacion entre paquetes TCP de entrada" "Tiempo (seg)" "Probabilidad" resultadoEj5.tmp graficaTiempoTCPIn.jpeg


./ecdf.sh timeipout.tmp > resultadoEj5.tmp

./grafica.sh "ECDF de los tiempos de separacion entre paquetes TCP de salida" "Tiempo (seg)" "Probabilidad" resultadoEj5.tmp graficaTiempoTCPOut.jpeg

./ecdf.sh timeudpin.tmp > resultadoEj5.tmp

./grafica.sh "ECDF de los tiempos de separacion entre paquetes UDP de entrada" "Tiempo (seg)" "Probabilidad" resultadoEj5.tmp graficaTiempoUDPIn.jpeg

./ecdf.sh timeudpout.tmp > resultadoEj5.tmp

./grafica.sh "ECDF de los tiempos de separacion entre paquetes UDP de salida" "Tiempo (seg)" "Probabilidad" resultadoEj5.tmp graficaTiempoUDPOut.jpeg

rm resultadoEj5.tmp
