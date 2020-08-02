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
import colorama
# from prettytable import PrettyTable
from socket import *
import random
from scapy.all import *
from threading import Thread
import pandas
from gif_for_cli.execute import execute
import argparse
from subprocess import run, PIPE


#####COLORAMA PARMS
colorama.init(autoreset=True)
# ---------only after debug----------
# hide some errors from shell
class DevNull:
    def write(self, msg):
        pass
sys.stderr = DevNull()
######ARGUMENTS GEN
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
    print("\nInitializinf Arcadia Asrenal \n\n\n ")
    from network import *
    time.sleep(0.1)
    from wifi_features import *
    time.sleep(0.1)
    from bruteforcers import *
    time.sleep(1.5)
else:
    os.system("clear && python3 -m gif_for_cli --rows 25 --cols 50 gifs/albator.gif")
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\nInitializinf Arcadia Asrenal \n\n\n ")
    from network import *
    time.sleep(0.1)
    from wifi_features import *
    time.sleep(0.1)
    from bruteforcers import *
    time.sleep(1.5)
# currentdate = date.today()
# currentdate = currentdate.strftime('%d:%m:%y ')
# current = datetime.now()
# current_time = current.strftime("%H:%M:%S")
def template():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Style.BRIGHT+Fore.GREEN+"""
    __  __           __           __      ____               _           __
   / / / /___ ______/ /___  _____/ /__   / __ \_________    (_)__  _____/ /_
  / /_/ / __ `/ ___/ / __ \/ ___/ //_/  / /_/ / ___/ __ \  / / _ \/ ___/ __/
 / __  / /_/ / /  / / /_/ / /__/ ,<    / ____/ /  / /_/ / / /  __/ /__/ /_
/_/ /_/\__,_/_/  /_/\____/\___/_/|_|  /_/   /_/   \____/_/ /\___/\___/\__/
                                                      /___/
      A Satcom Script for Pentesting
    """)
    pass

def install_dependencies():
    os.system("xterm -e 'systemctl start postgresql && msfdb init && msfconsole -x db_status'")

if __name__ == '__main__':
    def menu():
        template()
        #time.sleep(1)
        print()

        choice = input(Style.BRIGHT+Fore.YELLOW+"""
              1: Update OS
              2: Starting 'The Galaxy Railways' Protocol
              3: 'Death Shadow' Network Blaster
              4: Wifi Arsenal
              5: Bruteforcers
              00: Quit/Log Out

      Please enter your choice: """)

        if choice =="1":
            template()
            os.system("xterm -e 'sudo apt update && sudo apt upgrade -f && sudo apt install ffmpeg zlib* libjpeg* python3-setuptools'")
            pass
        elif choice =="2":
            print("actually nothing")
        elif choice =="3":
            template()
            choice = input("""
              1: Port Scanner

              b: back
              00: Quit/Log Out

              Please enter your choice: """)

            if choice =="1":
                template()
                target = input("Target IP/Range: ")
                portscanner()
            elif choice =="2":
                pass
            elif choice == "3":
                pass
            elif choice == "b":
                menu()
            elif choice == "00":
                sys.exit

        elif choice=="4":
            template()
            choice = input("""
              1: Wifi Scanner
              2: Wifi Deauther

              b: back
              00: Quit/Log Out

              Please enter your choice: """)

            if choice =="1":
                Wifi_scanner()
            elif choice =="2":
                template()
                interface =input("Interface: ")
                mactarget =input("Target Mac Address: ")
                packets =input("Packet(default: 999): ")
                Wifi_deauther(interface, mactarget, packets)
            elif choice == "3":
                pass
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
# from from prettytable import PrettyTable import AsciiTable
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
