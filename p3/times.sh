#!/bin/bash
# Archivo que recibe un fichero como primer argumento con los tiempos
# entre paquetes y devuelve dos columnas: la primera con un tiempo
# y la segunda con cuantas veces aparece ese tiempo en el fichero de entrada

awk '{array[$0]+=1; keys[$0]=$0;} END{for(key in keys){printf("%s\t%s\n", key, array[key]);}}' $1
