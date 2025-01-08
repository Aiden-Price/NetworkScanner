import re
import subprocess
import socket
import ipaddress
import concurrent.futures
import networkx as nx
import matplotlib.pyplot as plt
from dominate import document
from dominate.tags import h1, p
import schedule
import time

# Regular Expression Pattern to recognize IPv4 addresses and CIDR notation.
ip_add_range_pattern = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$"
)

# Validate IP address range input
while True:
    ip_address_range = input("IP Address Range (e.g., 192.168.1.0/24): ")
    if ip_add_range_pattern.match(ip_address_range):
        print(f"{ip_address_range} is valid")
        break
    else:
        print("Invalid IP range. Try again.")

# Subnet Calculation
subnet = ipaddress.ip_network(ip_address_range, strict=False)
print(f"Subnet: {subnet}")
print(f"Total Hosts: {subnet.num_addresses}")
print(f"Usable Hosts: {subnet.num_addresses - 2}")
hosts = [str(host) for host in subnet.hosts()]

# Perform ARP scan using `arp-scan`
print(f"\n--- Performing ARP Scan on {ip_address_range} ---")
try:
    result = subprocess.run(
        ["arp-scan", "--localnet", ip_address_range],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(result.stdout)
except FileNotFoundError:
    print("Error: `arp-scan` is not installed on your system. Skipping ARP scan.")
except Exception as e:
    print(f"An error occurred during the ARP scan: {e}")

# Multi-threaded Ping Scan
def ping_host(ip):
    try:
        response = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if response.returncode == 0:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return f"Active: {ip} (Hostname: {hostname})"
            except socket.herror:
                return f"Active: {ip} (Hostname: Unknown)"
        else:
            return f"Inactive: {ip}"
    except Exception as e:
        return f"Error for {ip}: {e}"

print("\n--- Performing Ping Scan ---")
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    ping_results = list(executor.map(ping_host, hosts))
for result in ping_results:
    if result and "Active" in result:
        print(result)

# Nmap Scan
def nmap_scan(ip_range):
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-sV", "-O", "-A", "-p-", "--script", "vuln", ip_range],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout
    except FileNotFoundError:
        return "Error: Nmap is not installed. Please install it and try again."
    except Exception as e:
        return f"Error during Nmap scan: {e}"

print("\n--- Performing Nmap Scan ---")
nmap_results = nmap_scan(ip_address_range)
print(nmap_results)

# Network Mapping Visualization
def visualize_network(ping_results):
    graph = nx.Graph()
    for result in ping_results:
        if "Active" in result:
            ip = result.split()[1]
            hostname = result.split('(')[-1].strip(')')
            graph.add_node(ip, label=hostname)
    nx.draw(graph, with_labels=True, node_size=500, font_size=10)
    plt.show()

print("\n--- Visualizing Network ---")
visualize_network(ping_results)

# Credential Brute-forcing (using hydra)
def brute_force(ip, service, username, password_file):
    try:
        print(f"\n--- Brute-forcing {service} on {ip} ---")
        result = subprocess.run(
            ["hydra", "-l", username, "-P", password_file, f"{service}://{ip}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(result.stdout)
    except FileNotFoundError:
        print("Error: Hydra is not installed. Please install it and try again.")
    except Exception as e:
        print(f"Error during brute-forcing: {e}")

# Example brute-forcing SSH on the first active IP
first_active_ip = next((res.split()[1] for res in ping_results if "Active" in res), None)
if first_active_ip:
    brute_force(first_active_ip, "ssh", "admin", "passwords.txt")

# Generate HTML Report
def generate_html_report(ping_results, nmap_results):
    doc = document(title="Network Scan Report")
    with doc:
        h1("Network Scan Report")
        p("Ping Results:")
        for result in ping_results:
            p(result)
        p("Nmap Results:")
        p(nmap_results)
    with open("scan_report.html", "w") as f:
        f.write(doc.render())

print("\n--- Generating HTML Report ---")
generate_html_report(ping_results, nmap_results)

user_schedule_choice = input("Schedule a scan? (y/n)")
if user_schedule_choice == 'y':

    #Scheduling
    def scheduled_scan():
        print("\n--- Scheduled Scan Started ---")
        ping_results = list(executor.map(ping_host, hosts))
        nmap_results = nmap_scan(ip_address_range)
        generate_html_report(ping_results, nmap_results)
        print("\n--- Scheduled Scan Completed ---")

    schedule.every().day.at("00:00").do(scheduled_scan)

    print("\n--- Scheduling Daily Scan at 00:00 ---")
    while True:
        schedule.run_pending()
        time.sleep(1)

print("\n--- Scan Complete !! ---")
