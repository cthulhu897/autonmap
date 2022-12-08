#!/bin/bash
echo "[parsing]"

for file in $(find . -type f -name "*.csv");
do
    ip=$(echo $file | awk '{ print substr( $0, 3 ) }')
    ip=$(echo "${ip/".csv"/""}"   )
    ports=$(cat $file | xargs | tr ' ' ',')

    
    echo "nmap -sS -sVC -p $ports -T3 $ip"
done;