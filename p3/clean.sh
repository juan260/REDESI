#!/bin/bash
# Script que limpia todos los archivos temporales

echo "-----------------------------"
echo "Limpiando archivos temporales..."
rm -f ipfile allfile ipsrcfile.tmp ipdstfile.tmp tcpdstfile.tmp tcpsrcfile.tmp udpdstfile.tmp udpsrcfile.tmp
echo "Limpieza completada"
