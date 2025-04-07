#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
###########################################################
#                                                         #
#                      fscan - Port Scanner               #
#                                                         #
# Author: fuysaal                                         #
# Description: A simple port scanner that scans a range   #
# of ports on a target server and provides service info.  #
#                                                         #
# Version: 1.0                                            #
# Created on: 2025-04-07                                  #
#                                                         #
# Dependencies:                                            #
#   - socket                                               #
#   - threading                                            #
#   - requests                                             #
#   - random                                               #
#   - string                                               #
#                                                         #
# Usage:                                                   #
#   1. Run the script: python3 fscan.py                    #
#   2. Enter the target IP/domain and the range of ports. #
#                                                         #
# License:                                                 #
#   MIT License                                            #
#                                                         #
# GitHub: https://github.com/yourusername/fscan            #
#                                                         #
###########################################################

   	   @@@@@  @@@@@   @@@@@   @@@@@  @    @     
   	   @      @       @       @   @  @@   @     
   	   @@@    @@@@@   @       @@@@@  @ @  @     
   	   @          @   @       @   @  @  @ @     
   	   @      @@@@@   @@@@@   @   @  @    @		

"""

import socket
import threading
import time
import requests
import random
import string

open_ports = []
lock = threading.Lock()
TIMEOUT = 1.5

def rand_str(len_):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(len_))

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def retrieve_info(service_type, target, port):
    if service_type in ['http', 'https']:
        return get_http_info(target, port)
    elif service_type == 'mongodb':
        return get_mongo_info(target, port)
    elif service_type == 'ftp':
        return get_ftp_info(target, port)
    elif service_type == 'postgresql':
        return get_postgres_info(target, port)
    elif service_type == 'ssh':
        return get_ssh_info(target, port)
    else:
        return generic_service_info(target, port)

def get_http_info(target, port):
    try:
        status = fetch_http_status(target, port)
        server = requests.get(f"http://{target}:{port}", timeout=TIMEOUT).headers.get('Server', 'Unknown')
        return f"HTTP {status} - {server}"
    except requests.exceptions.RequestException:
        return "Error"

def fetch_http_status(target, port):
    try:
        url = f"http://{target}:{port}"
        return requests.get(url, timeout=TIMEOUT).status_code
    except requests.exceptions.RequestException:
        return "Error"

def get_mongo_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        sock.send(b"\x16\x00\x00\x00\x00\x00\x00\x00")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def get_ftp_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def get_postgres_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def get_ssh_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def generic_service_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def scan_single_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
            with lock:
                open_ports.append(port)
        sock.close()
    except socket.error:
        pass

def execute_scan(target, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_single_port, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def write_scan_results(target, open_ports):
    with open("scan_results.txt", "w") as f:
        f.write(f"Scan results for {target}:\n")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, 'tcp')
                version = retrieve_info(service, target, port)
                f.write(f"Port {port}: {service} - Version: {version}\n")
            except Exception as e:
                f.write(f"Port {port}: Error: {e}\n")

def main():
    
    print("""
===========================================================
   	   @@@@@  @@@@@   @@@@@   @@@@@  @    @     
   	   @      @       @       @   @  @@   @     
   	   @@@    @@@@@   @       @@@@@  @ @  @     
   	   @          @   @       @   @  @  @ @     
   	   @      @@@@@   @@@@@   @   @  @    @		
===========================================================
    """)

    input_target = input("Enter target IP or domain: ")
    target_ip = resolve_target(input_target)
    
    if target_ip is None:
        print("Invalid target.")
        return

    print(f"Target IP resolved: {target_ip}")

    start_port = int(input("Starting port: "))
    end_port = int(input("Ending port: "))

    start_time = time.time()

    execute_scan(target_ip, start_port, end_port)

    if open_ports:
        print("Port\tStatus\tService\tVersion")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, 'tcp')
                version = retrieve_info(service, input_target, port)
            except OSError:
                service = ""
                version = ""
            print(f"{port}\topen\t{service}\t{version}")
    else:
        print("No open ports found.")

    end_time = time.time()
    print(f"Scan completed in {end_time - start_time} seconds.")

    write_scan_results(input_target, open_ports)

if __name__ == "__main__":
    main()
