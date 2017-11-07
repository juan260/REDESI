#!/bin/bash
# Script que muestra el porcentaje de bytes ip y no ip, y dentro de
# los que sean ip los udp, tcp u otros (ip es ethernet = 0x0800
# o ethernet de tipo vlan (0x8100) con tipo vlan ip (0x0800)

tshark -r traza.pcap -T fields -e eth.type -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > tmpfile

countlines = wc -l < tmpfile

rm tmpfile

print $countlines


