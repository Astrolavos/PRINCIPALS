from scapy.all import sniff, IP, Ether, TCP, UDP
import pandas as pd
import numpy as np
import os
# command line args
import argparse
from tqdm import tqdm
import logging

from queue import Queue
from threading import Thread

def capture_packets(captured_packets: Queue, interface='eth0', count=100):
    logging.info(f"Starting capture packets for interface {interface}")
    sniff(prn= lambda x: captured_packets.put(x), iface=interface, filter="ip and (tcp or udp)", count=count)
    captured_packets.put(None)
    logging.info(f"Ending capture packets for interface {interface}")

def fake_capture_packets(captured_packets: Queue, filename, count=100):
    logging.info(f"Starting fake capture packets for file {filename}")
    sniff(prn= lambda x: captured_packets.put(x), offline=filename, lfilter=lambda x: IP in x and (TCP in x or UDP in x), count=count)
    captured_packets.put(None)
    logging.info(f"Ending fake capture packets for file {filename}")

def get_own_ip(interface='eth0'):
    f = os.popen(f'ip -f inet addr show  {interface} | grep "inet"')
    data = f.read()
    ip_address = data.strip().split(' ')[1]
    # Remove the subnet mask
    ip_address = ip_address.split('/')[0]
    return ip_address

def is_packet_outgoing(packet, target):
    # Assumes packet has IP and Ether
    if packet[IP].src.startswith(target):
        return True
    if packet[IP].dst.startswith(target):
        return False
    return None

def var_or_zero(series):
    if len(series) <= 1:
        return 0
    return series.var()

def mean_or_zero(series):
    if len(series) == 0:
        return 0
    return series.mean()

from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from collections import deque, defaultdict


from typing import Dict
from dataclasses import dataclass



@dataclass
class Packet:
    source_ip: str
    mac_ip: str
    channel: str
    socket: str
    arrival_time: float
    size: int
    is_outbound: bool


def compute_stats(packet_queue: Queue[Packet], window_size: float, results: Queue):
    groupings = defaultdict(lambda : defaultdict(deque))
    logging.info(f"Starting compute stats for window size {window_size}")
    while True:
        stats = {}
        new_packet =  packet_queue.get()
        if new_packet is None:
            results.put(None)
            break
        logging.debug(f"Processing packet {new_packet}")
        arrival_time = new_packet.arrival_time
        # get the groupings for each column
        for column in ['source_ip', 'mac_ip', 'channel', 'socket']:
            packets_to_process = groupings[column][new_packet.__dict__[column]]

            # Remove packets that are too old from the right side of the queue
            packets_to_process.appendleft(new_packet)
            while packets_to_process[0].arrival_time < arrival_time - window_size:
                packets_to_process.pop()
            
            df = pd.DataFrame(packets_to_process)
            update_stats_dict(column, window_size, new_packet, df, stats)
        
        results.put(stats)
    logging.info(f"Ending compute stats for window size {window_size}")

def update_stats_dict(column, time_range, row, df, stats):
    # Get packet_size_stats
    if row.is_outbound == True:
        # Get the subset of data that we want to focus on
        stats[f"{column}_mean_out_pckt_size_{time_range}"] = df['size'].mean()
        stats[f"{column}_var_out_pckt_size_{time_range}"] = var_or_zero(df['size'])
    else:
        # Get the subset of data that we want to focus on
        stats[f"{column}_mean_out_pckt_size_{time_range}"] = 0
        stats[f"{column}_var_out_pckt_size_{time_range}"] = 0

    # Get packet count
    stats[f"{column}_pckt_count_{time_range}"] = len(df['size'])

    # Get mean, variance jitter, or the difference in arrival times
    if column == 'channel':
        jitter = df.index.to_series().diff().dropna()
        stats[f"{column}_jitter_mean_{time_range}"] = jitter.mean()
        stats[f"{column}_jitter_var_{time_range}"] = var_or_zero(jitter)
        # For the "number", just compute the difference since the last measurement.
        # Get the last entry in the jitter dataframe
        jitter_number = 0
        if len(jitter) > 0:
            jitter_number = jitter.iloc[-1]
        stats[f"{column}_jitter_count_{time_range}"] = jitter_number

    if column in ['channel', 'socket']:
        # For weight, get the count of entries
        stats[f"{column}_weight_pckt_size_{time_range}"] = len(df['size'])
        # for mean and variance, get the mean of the packet size
        stats[f"{column}_mean_pckt_size_{time_range}"] = df['size'].mean()
        stats[f"{column}_var_pckt_size_{time_range}"] = var_or_zero(df['size'])

        # For radius, get the root squared sum of the variances between the inbound and outbound packets
        outbound = df[df['is_outbound'].values]['size']
        inbound = df[~df['is_outbound'].values]['size']
        inbound_var = var_or_zero(inbound)
        outbound_var = var_or_zero(outbound)
        stats[f"{column}_radius_pckt_size_{time_range}"] = (inbound_var**2 + outbound_var**2)**0.5

        # For magnitude, get the root squared sum of the means between the inbound and outbound packets
        inbound_mean = mean_or_zero(inbound)
        outbound_mean = mean_or_zero(outbound)
        stats[f"{column}_magnitude_pckt_size_{time_range}"] = (inbound_mean**2 + outbound_mean**2)**0.5

        # This is extremely slow compared to the other steps. Excluded for now.
        # compute_cov_and_pcc(df, column, time_range, stats)

# Function to process packets
def process_packets(captured_packets: Queue, target, window_size_queues: Dict[float, Queue]):
    logging.info("Starting process packets")
    data = []
    while True:
        packet = captured_packets.get()
        if packet is None:
            for queue in window_size_queues.values():
                queue.put(None)
            break

        if IP in packet and Ether in packet and (TCP in packet or UDP in packet):
            is_outbound = is_packet_outgoing(packet, target)
            if is_outbound is None:
                continue
            if is_outbound:
                external_ip = packet[IP].dst
                external_port = packet[IP].dport
                internal_ip = packet[IP].src
                internal_port = packet[IP].sport
            else:
                external_ip = packet[IP].src
                external_port = packet[IP].sport
                internal_ip = packet[IP].dst
                internal_port = packet[IP].dport


            size = len(packet)
            arrival_time = packet.time
            mac_ip = (packet[Ether].src, packet[IP].src)
            channel = (internal_ip, external_ip)
            socket = (internal_ip, internal_port, external_ip, external_port)
            parsed_packet = Packet(packet[IP].src, str(mac_ip), str(channel), str(socket), arrival_time, size, is_outbound)

            for window_size, queue in window_size_queues.items():
                queue.put(parsed_packet)
        else:
            assert False, "This should never happen since filtering happens at the sniff function"
    logging.info("Ending process packets")

def combine_results(window_size_outputs: Dict[float, Queue], output_file):
    progress = tqdm()
    # Write output as csv
    with open(output_file, "w") as output_file:
        # Get the first row and use it to write the header and its data
        packet_data_row = {}
        for window_size, queue in window_size_outputs.items():
            packet_data_row.update(queue.get())
        output_file.write(",".join(packet_data_row.keys()) + "\n")
        output_file.write(",".join([str(x) for x in packet_data_row.values()]) + "\n")
        while True:
            packet_data_row = {}
            for window_size, queue in window_size_outputs.items():
                data = queue.get()
                if data is None:
                    return
                packet_data_row.update()
            output_file.write(",".join([str(x) for x in packet_data_row.values()]) + "\n")
            progress.update(1)

import multiprocessing
def main():
    parser = argparse.ArgumentParser(description='Capture traffic')

    parser.add_argument('--interface', type=str, default='eno1',
                        help='Interface to capture traffic on')
    
    parser.add_argument('--count', type=int, default=100,
                        help='Number of packets to capture')
    
    parser.add_argument('--filename', type=os.path.abspath, default=None,
                        help='Filename to read packets from')
    
    parser.add_argument('--output', type=os.path.abspath, default="output.csv")

    parser.add_argument('--target', type=str, help='Target IP address to capture traffic for')

    parser.add_argument( '-log',
                        '--loglevel',
                        default='warning',
                        help='Provide logging level. Example --loglevel debug, default=warning' )


    args = parser.parse_args()


    logging.basicConfig( level=args.loglevel.upper() )
    logging.info( f"Logging level set to {args.loglevel.upper()}" )

    # Create a thread that captures packets
    captured_packets = Queue()
    if args.filename is not None:
        Thread(target=fake_capture_packets, args=(captured_packets, args.filename, args.count)).start()
    else:
        Thread(target=capture_packets, args=(captured_packets, args.interface, args.count)).start()

    # We keep packets on each queue
    window_size_queues = {
        0.1: multiprocessing.Queue(),
        0.5: multiprocessing.Queue(),
        1.5: multiprocessing.Queue(),
        10: multiprocessing.Queue(),
        60: multiprocessing.Queue()
    }
    # Create a thread that processes packets and puts them on the queues
    Thread(target=process_packets, args=(captured_packets, args.target, window_size_queues)).start()

    window_size_outputs = {
        0.1: multiprocessing.Queue(),
        0.5: multiprocessing.Queue(),
        1.5: multiprocessing.Queue(),
        10: multiprocessing.Queue(),
        60: multiprocessing.Queue()
    }
    # Create separate threads for each window size. These could be separate processes eventually
    for window_size, queue in window_size_queues.items():
        multiprocessing.Process(target=compute_stats, args=(queue, window_size, window_size_outputs[window_size])).start()
    
    combine_results(window_size_outputs, args.output)
    logging.info("Done")

    # Aggregating and calculating mean and variance

if __name__ == "__main__":
    main()
