import socket
import threading
import time
import requests
import logging
import random
import string

open_ports = []
lock = threading.Lock()
TIMEOUT = 1.5

logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def gen_random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def get_target_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        logging.error(f"Unable to resolve IP for {target}.")
        return None

def fetch_service_info(service_type, target, port):
    try:
        if service_type == 'http' or service_type == 'https':
            return fetch_http_info(target, port)
        if service_type == 'mongodb':
            return fetch_mongo_info(target, port)
        if service_type == 'ftp':
            return fetch_ftp_info(target, port)
        if service_type == 'postgresql':
            return fetch_postgres_info(target, port)
        if service_type == 'ssh':
            return fetch_ssh_info(target, port)
        return generic_service_info(target, port)
    except Exception as e:
        return f"Error: {str(e)}"

def fetch_http_info(target, port):
    try:
        status_code = fetch_http_status(target, port)
        version = requests.get(f"http://{target}:{port}", timeout=TIMEOUT).headers.get('Server', 'Unknown')
        return f"HTTP {status_code} - {version}"
    except requests.exceptions.RequestException:
        return "Error"

def fetch_http_status(target, port):
    try:
        url = f"http://{target}:{port}"
        return requests.get(url, timeout=TIMEOUT).status_code
    except requests.exceptions.RequestException:
        return "Error"

def fetch_mongo_info(target, port):
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

def fetch_ftp_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def fetch_postgres_info(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "Error"

def fetch_ssh_info(target, port):
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

def attempt_scan(target, port):
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

def perform_scan(target, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=attempt_scan, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def save_scan_results(target, open_ports):
    with open("open_ports_results.txt", "w") as f:
        f.write(f"Results for {target}:\n")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, 'tcp')
                version = fetch_service_info(service, target, port)
                f.write(f"Port {port}: {service} - Version: {version}\n")
            except Exception as e:
                f.write(f"Port {port}: Error: {e}\n")
    logging.info(f"Scan results saved for {target}.")

def main():
    targets_input = input("Enter target IP or domain names (comma-separated): ")
    targets = [target.strip() for target in targets_input.split(',')]
    
    start_port = int(input("Starting port: "))
    end_port = int(input("Ending port: "))

    logging.info(f"Initiating scan for targets: {targets}...")
    start_time = time.time()

    for target in targets:
        ip_address = get_target_ip(target)
        if ip_address is None:
            continue
        perform_scan(ip_address, start_port, end_port)

    if open_ports:
        print("Port\tStatus\tService\tVersion")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, 'tcp')
                version = fetch_service_info(service, targets[0], port)
            except OSError:
                service = ""
                version = ""
            print(f"{port}\topen\t{service}\t{version}")
    else:
        print("No open ports found.")

    end_time = time.time()
    logging.info(f"Scan completed. Duration: {end_time - start_time} seconds.")
    print(f"Scan completed in {end_time - start_time} seconds.")

    save_scan_results(targets[0], open_ports)

if __name__ == "__main__":
    main()
