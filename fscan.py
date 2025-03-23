import socket
import threading
import time
import requests  # For sending HTTP requests

open_ports = []
lock = threading.Lock()
TIMEOUT = 1.5


def get_ip(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print("Target IP address could not be resolved.")
        return None


def get_service_version(service, target, port):
    if service == 'http' or service == 'https':
        try:
            url = f"http://{target}:{port}"
            response = requests.get(url, timeout=TIMEOUT)
            server_header = response.headers.get('Server')
            return server_header
        except requests.exceptions.RequestException:
            return ""

    if service == 'ftp':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'ssh':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'smtp':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    # New services added

    if service == 'telnet':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'mysql':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            sock.send(b"\\r\\n")
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'postgresql':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'redis':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            sock.send(b"*1\r\n$4\r\nINFO\r\n")
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'rdp':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'mssql':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    if service == 'vnc':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    return ""


def scan_port(target, port):
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


def port_scan(target, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
        for t in threads:
            t.join()
        for t in threads:
            t.join()


def save_results(target, open_ports):
    with open("open_ports.txt", "w") as f:
        f.write(f"Open ports for {target}:\n")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, "tcp")
                version = get_service_version(service, target, port)
                f.write(f"Port: {port}, Service: {service}, Version: {version}\n")
            except Exception as e:
                f.write(f"Port: {port}, Error: {e}\n")
    print("Results saved to open_ports.txt.")


def main():
    target = input("Enter target IP address or domain name: ")
    ip_address = get_ip(target)

    if ip_address is None:
        return

    print(f"IP address: {ip_address}")

    start_port = int(input("Enter starting port (e.g. 1): "))
    end_port = int(input("Enter ending port (e.g. 1024): "))

    print(f"Starting port scan for {ip_address}...")
    start_time = time.time()

    port_scan(ip_address, start_port, end_port)

    if open_ports:
        print("Port\tStatus\tService\t\tVersion")
        for port in open_ports:
            try:
                service = socket.getservbyport(port, 'tcp')
                version = get_service_version(service, ip_address, port)
            except OSError:
                service = ""
                version = ""

            print(f"{port}\topen\t{service}\t\t{version}")
    else:
        print("No open ports found.")

    end_time = time.time()
    print(f"Scan completed. Time: {end_time - start_time} seconds.")


if __name__ == "__main__":
    main()
