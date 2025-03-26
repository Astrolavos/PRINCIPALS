import subprocess

def block_ip(ip_address):
    # Execute the iptables command to block the IP
    if check_rule_exists(ip_address):
        print(f"IP address {ip_address} is already blocked")
        return
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True, check=True)
    print(f"Blocked IP address: {ip_address}")

def unblock_ip(ip_address):
    # Execute the iptables command to unblock the IP
    command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True, check=True)
    print(f"Unblocked IP address: {ip_address}")

def check_rule_exists(ip_address) -> bool:
    """ Check if the IP address is already blocked by iptables rule.
    """
    check_command = f"sudo iptables -C INPUT -s {ip_address} -j DROP"
    try:
        result = subprocess.run(check_command, shell=True, capture_output=True)
        if result.returncode == 0:
            return True
        return False
    except subprocess.CalledProcessError as e:
        return False


# IP address to block
# ip_to_block = "93.184.216.34"

# Call the function to block the IP
# unblock_ip(ip_to_block)