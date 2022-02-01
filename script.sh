#!/bin/bash


sed -i '/192.168.0.0/d' /etc/zmap/blacklist.conf # remove target IP from zmap's blacklist

echo "Starting scanning: "
date

IP="192.168.0.104"
ESP_IP="192.168.0.19"
REPEAT="3" # normally about 300
HPING_COUNT="3"

echo "NMAP"
nmap -sS -Pn -n $ESP_IP

echo "UNICORNSCAN FULL XMAS"
unicornscan -Iv -mTFSRPAU -R $REPEAT $IP --interface wlo1

echo "HPING3"
hping3 $IP -c $HPING_COUNT -V -p ++1 -A

echo "done..."
