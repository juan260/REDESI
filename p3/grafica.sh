#!/usr/bin/gnuplot

set title $1
set xlabel $2
set ylabel $3
plot $4 using 1:2 with lines
set term jpeg
set output $5
replot
