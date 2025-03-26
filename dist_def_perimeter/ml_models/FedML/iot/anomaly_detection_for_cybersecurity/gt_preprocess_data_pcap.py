from scapy.all import sniff, IP, Ether, TCP, UDP
import pandas as pd
import numpy as np
import os
# command line args
import argparse
from tqdm import tqdm

# Function to capture packets
def capture_packets(interface='eth0', count=100):
    return sniff(iface=interface, filter="ip", count=count)

def fake_capture_packets(filename, count=100):
    return sniff(offline=filename, lfilter=lambda x: IP in x, count=count)

def get_own_ip(interface='eth0'):
    f = os.popen(f'ip -f inet addr show  {interface} | grep "inet"')
    data = f.read()
    ip_address = data.strip().split(' ')[1]
    # Remove the subnet mask
    ip_address = ip_address.split('/')[0]
    return ip_address

def is_packet_outgoing(packet, myip):
    if IP in packet and Ether in packet:
        ##return packet[IP].src.startswith("192.168")
        return packet[IP].src == myip

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

def compute_stats(df):
    results = []
    df.arrival_time = df.arrival_time.astype('float64')
    df.set_index('arrival_time', inplace=True)
    for idx, row in tqdm(df.iterrows(), total=len(df)):
        stats = {}
        arrival_time = idx

        # Get all the rows that are the same along one column
        for column in ['source_ip', 'mac_ip', 'channel', 'socket']:
            # Get the rows that are the same along the column
            same_column = df[df[column].values == row[column]]

            for time_range in [0.1, 0.5, 1.5, 10, 60]:
                # Get all entries between the arrival time and "time_range" seconds before
                within_time_range = same_column[(same_column.index.values >= arrival_time - time_range) & (same_column.index.values <= arrival_time)]
                update_stats_dict(column, time_range, row, within_time_range, stats)

        results.append(stats)
    return pd.DataFrame(results)

import itertools
def compute_stats_parallel(df):
    results = []
    df.arrival_time = df.arrival_time.astype('float64')
    df.set_index('arrival_time', inplace=True)

    with multiprocessing.Manager() as manager:
        managed_df = manager.Value('df', df)
        with ProcessPoolExecutor(2) as executor: # TODO: To get loading bar, use submit and tqdm according to https://stackoverflow.com/questions/51601756/use-tqdm-with-concurrent-futures  
            for stats in executor.map(construct_stats_dict, itertools.repeat(managed_df), range(len(df))):

                results.append(stats)
    return pd.DataFrame(results)

def construct_stats_dict(managed_df, i):
    df = managed_df.value
    row = df.iloc[i]
    arrival_time = df.index.values[i]

    stats = {'row': i}
    # Get all the rows that are the same along one column
    for column in ['source_ip', 'mac_ip', 'channel', 'socket']:
        # Get the rows that are the same along the column
        same_column = df[df[column].values == row[column]]

        for time_range in [0.1, 0.5, 1.5, 10, 60]:
            # Get all entries between the arrival time and "time_range" seconds before
            within_time_range = same_column[(same_column.index.values >= arrival_time - time_range) & (same_column.index.values <= arrival_time)]
            update_stats_dict(column, time_range, row, within_time_range, stats)
    return stats

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
def process_packets(packets, interface='eno1', myip=None):
    data = []
    for packet in packets:
        if IP in packet and Ether in packet and (TCP in packet or UDP in packet):
            is_outbound = is_packet_outgoing(packet, myip)
            if is_outbound == True:
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

            data.append((packet[IP].src, str(mac_ip), str(channel), str(socket), arrival_time, size, is_outbound))
    return pd.DataFrame(data, columns=['source_ip', "mac_ip", 'channel', "socket", "arrival_time", 'size', "is_outbound"])

from collections import defaultdict



# Main function
def main():
    parser = argparse.ArgumentParser(description='Capture traffic')

    parser.add_argument('--interface', type=str, default='eno1',
                        help='Interface to capture traffic on')
    
    parser.add_argument('--count', type=int, default=100,
                        help='Number of packets to capture')
    
    parser.add_argument('--filename', type=os.path.abspath, default=None,
                        help='Filename to read packets from')
    
    parser.add_argument('--ip', type=str, default=None,
                        help='ip for the device')

    parser.add_argument('--outfile', type=str, default="stats.csv", help='output filename')

    args = parser.parse_args()

    if args.filename is not None:
        packets = fake_capture_packets(args.filename, count= args.count)
        print(len(packets), "packets captured from file as", args.ip)
    else:
        packets = capture_packets(interface=args.interface, count=args.count)
        print(len(packets), "packets captured")
    

    df = process_packets(packets,args.ip)
    print(df)
    #print(get_own_ip(interface='eno1'))
    stats = compute_stats(df)
    print(stats)
    stats.to_csv(args.outfile)


    # Aggregating and calculating mean and variance

if __name__ == "__main__":
    main()



# Alternate methods to try and speed up results


# This code is too slow, so we are skipping it
def compute_cov_and_pcc(df, column, time_range, stats):
    outbound_seq = []
    inbound_seq = []
    current_outbound = 0
    current_inbound = 0
    for i, packet in df.iterrows():
        if packet.is_outbound == True:
            current_outbound += packet['size']
        else:
            current_inbound += packet['size']
        if current_inbound == 0 or current_outbound == 0:
            continue
        outbound_seq.append(current_outbound)
        inbound_seq.append(current_inbound)
        current_inbound = 0
        current_outbound = 0
    
    cov = 0
    pcc = 0
    if len(outbound_seq) > 1:
        cov = np.cov(inbound_seq, outbound_seq)[0][1]
        pcc = np.corrcoef(inbound_seq, outbound_seq)[0][1]

        if np.isnan(cov):
            cov = 0
        if np.isnan(pcc):
            pcc = 0


    stats[f"{column}_cov_pckt_size_{time_range}"] = cov
    stats[f"{column}_pcc_pckt_size_{time_range}"] = pcc

