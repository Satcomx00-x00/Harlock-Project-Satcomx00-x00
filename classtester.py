#!/usr/bin/python3
# -*- coding: utf-8  -*-
# from wifi_features import *
import re
import socket
import netifaces

interface_list = netifaces.interfaces()
interface = filter(lambda x: 'wlan' in x,interface_list)
print(interface)
if_list = netifaces.interfaces()
print(if_list)
# interface_list = netifaces.interfaces()
# interface = filter(lambda x: 'eth' in x,interface_list)

#Wifi_deauther("wlan1mon", "A2:5E:0C:10:87:E7")
