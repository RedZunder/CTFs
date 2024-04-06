#!/bin/bash
#simple IP sweep program

if [ "$1" == "" ]
then
echo "Use: ./ipsweep.sh [3 octets of IP]."

else

for ip in `seq 1 254`; do
ping -c 1 $1.$ip | grep ":"| cut -d " " -f 4| tr -d ":" &
done

fi
