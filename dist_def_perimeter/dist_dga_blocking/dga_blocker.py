from scapy.all import *
import tldextract
from dga_data_receiver import block_ip
import requests
import json
import ipaddress

def get_db_domains():
    url = "http://localhost:5000/dga"
    response = requests.get(url)
    return [x['Body']['qname'] for x in response.json()]

def is_ipv6_address(ip_address):
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return ip_obj.version == 6
    except ValueError:
        return False

def process_traffic(pkt):
    if IP in pkt:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
            dns_response = pkt.getlayer(DNS)
            domain_name = pkt.getlayer(DNS).qd.qname.decode()
            if dns_response.ancount == 0:
                return
            
            for answer in dns_response.an:
                if not hasattr(answer, "rdata"):
                    continue

                ip_address = answer.rdata
                print(f"Domain {domain_name} IP Address: {ip_address}")
                if is_ipv6_address(ip_address):
                    continue

                input_domain = tldextract.extract(domain_name).domain
                domains = get_db_domains()
                if input_domain in domains:
                    print("match domain", input_domain)
                    block_ip(ip_address)               
def capture_traffic(interface_name):
    sniff(iface = interface_name, prn = process_traffic, store = 0)
    

interface_name = sys.argv[1]
capture_traffic(interface_name)