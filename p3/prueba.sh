#!/bin/bash
n=$(wc -l < ejemplo.txt)
sort -n  ejemplo.txt |uniq -c | awk '{ array[$2] = array[$2 -1] + $1; print $2, array[$2]; }' > resprueba.txt
#en el print array[$2] debería ser array[$2]/$n para que nos diese la probabilidad
