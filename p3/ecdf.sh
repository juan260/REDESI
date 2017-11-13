#!/bin/bash
# Calcula las ecfd del archivo como primer parametro

sort -n  $1 |uniq -c | awk '{array[NR]=array[NR-1]+$1;array2[NR]=$2;} END{for(i=1;i<=NR;i++){printf("%s\t%s\n", array2[i], array[i]/array[NR]);}}' | sort -n


