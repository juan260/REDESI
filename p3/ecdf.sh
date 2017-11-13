#!/bin/bash
# Calcula las ecfd del archivo como primer parametro

sort -n  $1 |uniq -c #| awk '{ array[$2] = array[$2 -1] + $1; keys[$2]=$2; finalkey=$2;} END{for(key in keys){printf("%s\t%s\n",key, array[key]/array[finalkey]);} }'

