#!/bin/bash
#Almacena en un ECDF los tamaños de los paquetes leidos, y grafica el resultado.
#Este proceso lo ejecuta con los distintos flujos por MAC, HTTP y DNS. Para
#cada uno de estos analiza el trafico cada sentido.
#MAC origen
if ! [ -e macsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.src == 00:11:88:cc:33:21' > macsrcfile.tmp

fi

./ecdf.sh macsrcfile.tmp > graficamacsrc.tmp
./grafica.sh "ECDF de los tamaños a nivel 2 de los paquetes de la traza (sentido salida)" "Tamaño paquete" "Probabilidad" "graficamacsrc.tmp" "graficamacsrc.jpeg" "Tamaño"

#MAC destino
if ! [ -e macdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.dst == 00:11:88:cc:33:21' > macdstfile.tmp

fi

./ecdf.sh macdstfile.tmp > graficamacdst.tmp
./grafica.sh "ECDF de los tamaños a nivel 2 de los paquetes de la traza (sentido entrada)" "Tamaño paquete" "Probabilidad" "graficamacdst.tmp" "graficamacdst.jpeg" "Tamaño"


#HTTP origen
if ! [ -e httpsrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.srcport == 80' > httpsrcfile.tmp

fi

./ecdf.sh httpsrcfile.tmp > graficahttpsrc.tmp
./grafica.sh "ECDF de los tamaños a nivel 3 de los paquetes HTTP de la traza (sentido salida)" "Tamaño paquete" "Probabilidad" "graficahttpsrc.tmp" "graficahttpsrc.jpeg" "Tamaño"


#HTTP destino
if ! [ -e httpdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.dstport == 80' > httpdstfile.tmp

fi


./ecdf.sh httpdstfile.tmp > graficahttpdst.tmp
./grafica.sh "ECDF de los tamaños a nivel 3 de los paquetes HTTP de la traza (sentido entrada)" "Tamaño paquete" "Probabilidad" "graficahttpdst.tmp" "graficahttpdst.jpeg" "Tamaño"

#DNS origen
if ! [ -e dnssrcfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.srcport == 53' > dnssrcfile.tmp

fi

./ecdf.sh dnssrcfile.tmp > graficadnssrc.tmp
./grafica.sh "ECDF de los tamaños a nivel 3 de los paquetes DNS de la traza (sentido salida)" "Tamaño paquete" "Probabilidad" "graficadnssrc.tmp" "graficadnssrc.jpeg" "Tamaño"

#DNS destino
if ! [ -e dnsdstfile.tmp ]
then
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.dstport == 53' > dnsdstfile.tmp

fi

./ecdf.sh dnsdstfile.tmp > graficadnsdst.tmp
./grafica.sh "ECDF de los tamaños a nivel 3 de los paquetes DNS de la traza (sentido entrada)" "Tamaño paquete" "Probabilidad" "graficadnsdst.tmp" "graficadnsdst.jpeg" "Tamaño"

