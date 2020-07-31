#!/usr/bin/python3
# -*- coding: utf-8  -*-
# SATCOM
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
import argparse
from subprocess import run, PIPE

from network import *
from wifi_features import *
from bruteforcers import *

desc = 'Harlock Project is an Open Source and Python based program for pentesters to auditing network infrastructures.'
parser = argparse.ArgumentParser(prog="Harlock", usage='%(prog)s [options]', description=desc)
parser.add_argument("-V", "--version", help="show program version", action="store_true")
parser.add_argument("-NS", "--nosplash", help="disable startup splash screen", action="store_true")
parser.parse_args()
# Read arguments from the command line
args = parser.parse_args()
if args.version:
    print("Harlock Project version 0.1")
if args.nosplash:
    os.system('cls' if os.name == 'nt' else 'clear')
else:
    os.system("clear && python3 -m gif_for_cli --rows 25 --cols 50 gifs/albator.gif")
# currentdate = date.today()
# currentdate = currentdate.strftime('%d:%m:%y ')
# current = datetime.now()
# current_time = current.strftime("%H:%M:%S")

def template():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
    __  __           __           __      ____               _           __
   / / / /___ ______/ /___  _____/ /__   / __ \_________    (_)__  _____/ /_
  / /_/ / __ `/ ___/ / __ \/ ___/ //_/  / /_/ / ___/ __ \  / / _ \/ ___/ __/
 / __  / /_/ / /  / / /_/ / /__/ ,<    / ____/ /  / /_/ / / /  __/ /__/ /_
/_/ /_/\__,_/_/  /_/\____/\___/_/|_|  /_/   /_/   \____/_/ /\___/\___/\__/
                                                      /___/

    """)
    pass

def wifi_scanner():
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


    if __name__ == "__main__":
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





if __name__ == '__main__':
    def menu():
        template()
        #time.sleep(1)
        print()

        choice = input("""
                          1: Update OS
                          2: Starting Arcadia Protocol (Spec Recon)
                          3: Network Blaster
                          4: Wifi Arsenal
                          5: Bruteforcer
                          00: Quit/Log Out

                          Please enter your choice: """)

        if choice =="1":
            template()
            os.system("xterm -e 'sudo apt update && sudo apt upgrade -f && sudo apt install ffmpeg zlib* libjpeg* python3-setuptools'")
        elif choice =="2":
            print("actually nothing")
        elif choice =="3":
            print("test")
        elif choice=="4":
            template()
            choice = input("""
                              1: Wifi Scanner
                              2: Wifi Deauther

                              b: back
                              00: Quit/Log Out

                              Please enter your choice: """)

            if choice =="1":
                wifi_scanner()
            elif choice =="2":
                wifi_deauther()
            elif choice == "b":
                menu()
            elif choice == "00":
                sys.exit

        elif choice=="5":
            choice = input("""
                              1: SSH Bruteforcer
                              2: FTP Bruteforcer

                              b: back
                              00: Quit/Log Out

                              Please enter your choice: """)

            if choice =="1":
                ssh_bruteforcer()
            elif choice =="2":
                ftp_bruteforcer()
            elif choice == "b":
                menu()
            elif choice == "00":
                sys.exit

        elif choice=="00":
            sys.exit
        else:
            print("Selection: ")
            print("Please try again")
            menu()
    menu()

####CODE template
# from terminaltables import AsciiTable
# table_data = [
#     ['Heading1', 'Heading2'],
#     ['row1 column1', 'row1 column2'],
#     ['row2 column1', 'row2 column2'],
#     ['row3 column1', 'row3 column2']
# ]
# table = AsciiTable(table_data)
# print table.table
# +--------------+--------------+
# | Heading1     | Heading2     |
# +--------------+--------------+
# | row1 column1 | row1 column2 |
# | row2 column1 | row2 column2 |
# | row3 column1 | row3 column2 |
# +--------------+--------------+
