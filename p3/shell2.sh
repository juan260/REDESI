#!/bin/bash
# Script que muestra el porcentaje de bytes ip y no ip, y dentro de
# los que sean ip los udp, tcp u otros (ip es ethernet = 0x0800
# o ethernet de tipo vlan (0x8100) con tipo vlan ip (0x0800)

tshark -r traza.pcap -T fields -e eth.type -Y 'eth.type == 0x0800 or (eth.type == 0x8100 and vlan.etype == 0x0800)' > tmpfile

number=0
awk 'BEGIN{n_lines=0;} {n_lines=n_lines+1} END{print n_lines}' tmpfile

BEGIN{
        FS="\t";

            } {
                
                        total=total+1;
                                // Si es ip
                                        if ($1 == 0x0800 || $1 == 0x8100 and $3 == 0x0800){
                                                    ip=ip+1;
                                                        }END{print "\nTotal = ";
                                                                    print total;
                                                                                print "\n Ip = "
                                                                                            print ip}
rm tmpfile

echo "Hello, $LOGNAME, number of lines $number"

echo $countlines


