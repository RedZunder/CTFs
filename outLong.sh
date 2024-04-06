#!/bin/sh

#find a word in a file

if [ -f $1 ] && [ $2 != '' ] ;  then
	for i in `cat $1`:
	do
		echo $i | grep $2
	done
else
	echo "Usage: ./outLong.sh [file] [pattern]"
fi



