#!/bin/bash

set -x

echo -n 'module xbee2 +p' > /sys/kernel/debug/dynamic_debug/control

/usr/bin/killall -9 /usr/sbin/ldattach
sleep 1
ps -ef | grep ldattach
/sbin/rmmod xbee2
#/sbin/rmmod ieee802154
/sbin/modprobe ieee802154
/sbin/insmod ./xbee2.ko
sleep 1
/usr/sbin/ldattach -s 9600 -8 -n -1 25 $1
