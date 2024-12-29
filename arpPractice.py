import re
import subprocess
import socket

# Regular Expression Pattern to recognize IPv4 addresses.
ip_add_range_pattern = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$")

while True:
    # Prompt the user to enter a subnet (e.g., 192.168.2.0/24)
    # Use { ifconfig en0 | grep 'inet ' } to get IP address
    ip_address_range = input("IP Address Range: ")
    # Validate the input
    # Use match() for regex validation
    if ip_add_range_pattern.match(ip_address_range):  
        print(f"{ip_address_range} is valid")
        break
    else:
        print("Invalid IP range. Try again.")

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

# Perform Ping-based scan
print(f"\n--- Performing Ping Scan on {ip_address_range} ---")
# Extract the base IP and subnet mask
base_ip = ip_address_range.split('/')[0]
subnet_mask = int(ip_address_range.split('/')[1])

# Calculate the number of hosts based on the subnet mask
hosts = 2 ** (32 - subnet_mask) - 2  # Subtract 2 for network and broadcast addresses
print(f"Scanning {hosts} hosts in the range {ip_address_range}...\n")

for i in range(1, hosts + 1):
    # Increment the last octet of the base IP
    ip_to_ping = f"{base_ip.rsplit('.', 1)[0]}.{i}"
    try:
        # Ping the IP address
        response = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_to_ping],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # If the ping is successful, returncode will be 0
        if response.returncode == 0:
            try:
                # Attempt to resolve the hostname
                hostname, _, _ = socket.gethostbyaddr(ip_to_ping)
                print(f"Active: {ip_to_ping} (Hostname: {hostname})")
            except socket.herror:
                print(f"Active: {ip_to_ping} (Hostname: Unknown)")
    except Exception as e:
        print(f"Error occurred for {ip_to_ping}: {e}")

print("\n--- Scanning Complete ---")
