#!/bin/bash
modprobe mac80211_hwsim radios=2
nmcli dev set wlan0 managed no
nmcli dev set wlan1 managed no
iw dev wlan0 interface add mon0 type monitor
ip link set dev mon0 up
ip link set dev wlan0 up
