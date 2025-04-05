import socket
import os
import sys
import re
import subprocess

# Check and install missing dependencies
try:
    import requests
except ImportError:
    print("Installing required module: requests")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

def print_banner():
    print(r"""
     ____            _                _                _       
    / ___| ___ _ __| |_ _ __ ___  __| | ___ _ __ __ _| | __ _ 
   | |    / _ \ '__| __| '__/ _ \/ _` |/ _ \ '__/ _` | |/ _` |
   | |___|  __/ |  | |_| | |  __/ (_| |  __/ | | (_| | | (_| |
    \____|\___|_|   \__|_|  \___|\__,_|\___|_|  \__, |_|\__,_|
                                                  |___/       
    """)
    print("Cybersecurity Tool - Use responsibly on networks you own or have permission to test.")

def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return re.match(pattern, ip) is not None

def port_scanner(target_ip, port_range):
    print(f"Scanning {target_ip} for open ports in range {port_range}...")
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service_name = socket.getservbyport(port, 'tcp')
                open_ports.append((port, service_name))
                print(f"Port {port} is open (Service: {service_name})")
            else:
                print(f"Port {port} is closed.")
    return open_ports

def ping_sweep(subnet):
    print(f"Pinging subnet {subnet}...")
    active_hosts = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        if response == 0:
            active_hosts.append(ip)
            print(f"{ip} is active.")
    return active_hosts

def http_header_checker(url):
    print(f"Checking HTTP headers for {url}...")
    try:
        response = requests.get(url)
        headers = response.headers
        print("\nBasic Headers:")
        for header, value in headers.items():
            print(f"{header}: {value}")
        
        # Security header analysis with scoring
        security_headers = {
            'Strict-Transport-Security': {'weight': 2, 'msg': 'Recommended for HTTPS sites'},
            'Content-Security-Policy': {'weight': 3, 'msg': 'Critical to prevent XSS'},
            'X-Frame-Options': {'weight': 1, 'msg': 'Important to prevent clickjacking'},
            'X-Content-Type-Options': {'weight': 1, 'msg': 'Important to prevent MIME sniffing'},
            'Referrer-Policy': {'weight': 1, 'msg': 'Recommended to control referrer info'},
            'Permissions-Policy': {'weight': 1, 'msg': 'Recommended to restrict features'}
        }

        # Check which security headers are present
        print("\n\033[1mSecurity Analysis:\033[0m")
        total_score = 0
        max_score = sum(h['weight'] for h in security_headers.values())
        
        for header in security_headers:
            if header in headers:
                security_headers[header]['status'] = True
                total_score += security_headers[header]['weight']
                print(f"\033[32m✓ {header}: {headers[header]}\033[0m")
            else:
                security_headers[header]['status'] = False
                print(f"\033[31m✗ {header}: Missing - {security_headers[header]['msg']}\033[0m")
        
        # Calculate security score
        security_percentage = int((total_score / max_score) * 100)
        print(f"\n\033[1mSecurity Score: {security_percentage}%\033[0m")
        if security_percentage >= 80:
            print("\033[32mExcellent security headers implementation\033[0m")
        elif security_percentage >= 50:
            print("\033[33mModerate security headers implementation\033[0m")
        else:
            print("\033[31mPoor security headers implementation\033[0m")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching headers: {e}")

def banner_grabbing(target_ip, port):
    print(f"Grabbing banner from {target_ip}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((target_ip, port))
            sock.sendall(b'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(target_ip).encode())
            response = sock.recv(1024)
            print(f"Banner: {response.decode()}")
        except Exception as e:
            print(f"Error grabbing banner: {e}")

def main():
    print_banner()
    if len(sys.argv) > 1:
        # Command-line mode
        if sys.argv[1] == "--port-scan":
            target_ip = sys.argv[2]
            port_range = list(map(int, sys.argv[3].split('-')))
            port_scanner(target_ip, (port_range[0], port_range[1]))
        elif sys.argv[1] == "--ping-sweep":
            ping_sweep(sys.argv[2])
        elif sys.argv[1] == "--http-headers":
            http_header_checker(sys.argv[2])
        elif sys.argv[1] == "--banner-grab":
            banner_grabbing(sys.argv[2], int(sys.argv[3]))
        elif sys.argv[1] == "--help":
            print("Usage:")
            print("  --port-scan <IP> <start-end>  Scan ports on target IP")
            print("  --ping-sweep <subnet>        Ping sweep a subnet")
            print("  --http-headers <URL>         Check HTTP headers")
            print("  --banner-grab <IP> <port>    Grab service banner")
        return

    # Interactive mode
    while True:
        print("\nMenu:")
        print("1. Port Scanner")
        print("2. Ping Sweep")
        print("3. HTTP Header Checker")
        print("4. Banner Grabbing")
        print("5. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            target_ip = input("Enter target IP: ")
            if not validate_ip(target_ip):
                print("Invalid IP address.")
                continue
            port_range = input("Enter port range (e.g., 20-100): ")
            start_port, end_port = map(int, port_range.split('-'))
            port_scanner(target_ip, (start_port, end_port))
        elif choice == '2':
            subnet = input("Enter subnet (e.g., 192.168.1): ")
            ping_sweep(subnet)
        elif choice == '3':
            url = input("Enter URL (e.g., http://example.com): ")
            http_header_checker(url)
        elif choice == '4':
            target_ip = input("Enter target IP: ")
            port = int(input("Enter port: "))
            banner_grabbing(target_ip, port)
        elif choice == '5':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()