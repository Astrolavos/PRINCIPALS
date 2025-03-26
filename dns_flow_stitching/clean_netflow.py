#Program to clean, merge and orient netflow data
#Single processing version
#Input: Netflow data file name
#Output: Cleaned and merged netflow data csv file


import datetime
import re
import gzip
import sys
import os

clean_flows = []

ipv4_pattern = re.compile(r'^(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])(?:\.(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])){3}$')

def write_set_to_file(filename, input_set):
    with open(filename, 'w') as file:
        for item in input_set:
            file.write(str(item) + '\n')

def is_valid(fl):
    lst = fl.rstrip().split(",")
    if len(lst) < 10: #NetFlow record have missing values
        print(lst)
        return
    else:
        if int(float(lst[4])) == 0: #Check for ICMP
            return
        if int(float(lst[4])) == 53 or int(float(lst[5])) == 53:  #Check for dns flows
            return
        if not is_ipv4(lst[2]) or not is_ipv4(lst[3]):  #Remove IPv6
            return
        if is_private_ip(lst[2]) or is_private_ip(lst[3]):  #Check for private IP communication
            return
        if is_internal(lst[2]) and is_internal(lst[3]): #Check for internal communication
            return
        if lst[2] == "255.255.255.255" or lst[3] == "255.255.255.255" or lst[2] == "224.0.0.252" or lst[3] == "224.0.0.252" :
            return
        clean_flows.append(fl)
    return

ipv4_prefixes = ['1.2.'] #Add prefixes of internal IP addresses. For testing purposes using "1.2." as a IPv4 /16 prefix of the organization. 
def is_internal(ip_str):
    #Add code to check if the IP address is an internal IP address of the organization
    if any(ip_str.startswith(prefix) for prefix in ipv4_prefixes):
        return True
    return False

def is_private_ip(ip_address):
    if ip_address.startswith('10.'):
        return True
    elif ip_address.startswith('192.168.'):
        return True
    else:
        octets = ip_address.split(".")
        if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
            return True
        return False

def is_ipv4(address):
    return bool(ipv4_pattern.search(address))

def flow_merge(netflow_file):
    print("Started flow merge") #First pass to merge unidirectional flows to bidirectional flows and assigns the merged flow the direction of the flow with lowest timestamp
    fl_dict = {}
    for fl in clean_flows:
        try:
            lst = fl.rstrip().split(",")
            if (lst[2],lst[3],lst[4],lst[5],lst[6]) in fl_dict:            #If pair in dictionary
                nested_dict = fl_dict[(lst[2],lst[3],lst[4],lst[5],lst[6])]
                nested_dict['pkt_in'] = nested_dict['pkt_in'] + int(lst[8])
                nested_dict['bytes_in'] = nested_dict['bytes_in'] + float(lst[9]) 
                nested_dict['last_tstamp'] = float(lst[0])
                nested_dict['last_duration'] = float(lst[1])
                nested_dict['count_in'] = nested_dict['count_in'] + 1
                nested_dict['dur'] = (max(float(lst[0])+float(lst[1]),float(nested_dict['tstamp'])+float(nested_dict['dur'])) - min(float(lst[0]),float(nested_dict['tstamp'])))
                if float(lst[0]) < nested_dict['tstamp']:
                    nested_dict['tstamp'] = float(lst[0])
                fl_dict[(lst[2],lst[3],lst[4],lst[5],lst[6])] = nested_dict
            elif (lst[3],lst[2],lst[5],lst[4],lst[6]) in fl_dict:          #If reverse pair in dictionary
                nested_dict = fl_dict[(lst[3],lst[2],lst[5],lst[4],lst[6])]
                nested_dict['pkt_out'] = nested_dict['pkt_out'] + int(lst[8])
                nested_dict['bytes_out'] = nested_dict['bytes_out'] + float(lst[9]) 
                nested_dict['last_tstamp'] = float(lst[0])
                nested_dict['last_duration'] = float(lst[1])
                nested_dict['count_out'] = nested_dict['count_out'] + 1
                nested_dict['dur'] = (max(float(lst[0])+float(lst[1]),float(nested_dict['tstamp'])+float(nested_dict['dur'])) - min(float(lst[0]),float(nested_dict['tstamp'])))
                fl_dict[(lst[3],lst[2],lst[5],lst[4],lst[6])] = nested_dict
                if float(lst[0]) < nested_dict['tstamp']: #We need to switch the direction of the flow
                    nested_dict['tstamp'] = float(lst[0])
                    #Flip packets in and out
                    temp1 = nested_dict['pkt_in'] 
                    nested_dict['pkt_in'] = nested_dict['pkt_out']
                    nested_dict['pkt_out'] = temp1 
                    #Flip bytes in and out 
                    temp1 = nested_dict['bytes_in'] 
                    nested_dict['bytes_in'] = nested_dict['bytes_out']
                    nested_dict['bytes_out'] = temp1
                    #Flip count
                    temp1 = nested_dict['count_in'] 
                    nested_dict['count_in'] = nested_dict['count_out']
                    nested_dict['count_out'] = temp1
                    del fl_dict[(lst[3],lst[2],lst[5],lst[4],lst[6])]
                    fl_dict[(lst[2],lst[3],lst[4],lst[5],lst[6])] = nested_dict
            else:
                fl_dict[(lst[2],lst[3],lst[4],lst[5],lst[6])] = {'tstamp': float(lst[0]), 'dur': float(lst[1]), 'pkt_in': int(lst[8]), 'pkt_out': 0, 'bytes_in': int(lst[9]), 'bytes_out': 0, 'last_tstamp': float(lst[0]), 'last_duration': float(lst[1]), 'count_in': 1, 'count_out': 0}     #If completely new, write to file
        except Exception as e:
            continue

    print("Starting flow orienting") #Second pass to orient the flows correctly using port numbers

    n = open(netflow_file + "_clean.csv", 'w')
    for key in fl_dict:
        ip1 = key[0]
        port1 = int(float(key[2]))
        ip2 = key[1]
        port2 = int(float(key[3]))

        if (port1 <= 1023 and port2 <= 1023): #Both port well known - flow dropped
            continue
        elif (port1 >= 1024 and port1 <= 32767) and (port2 >= 1024 and port2 <= 32767): #Both port registered - flow dropped
            continue
        elif (port1 >= 32768 and port2 >= 32768): #Both port ephemeral - flow dropped
            continue
        elif (port1 <= 1023 and (port2 >= 1024 and port2 <= 32767)) or ((port1 >= 1024 and port1 <= 32767) and port1 <= 1023): #One registered and one well known - flow dropped
            continue
        else:
            if is_internal(ip1):
                if port1 <= 1023 or (port1 >= 1024 and port1 <= 32767): #Internal IP with registered or well known port - flow dropped
                    continue
                else: #Internal IP with ephemeral port communicating with external IP on well known or registered port - keep flow
                    nested_dict = fl_dict[key]
                    lst = [str(key[0]),str(key[1]),str(key[2]),str(key[3]),str(key[4]),\
                           str(nested_dict['tstamp']),str(nested_dict['dur']),\
                            str(nested_dict['pkt_in']), str(nested_dict['pkt_out']),\
                                str(nested_dict['bytes_in']),str(nested_dict['bytes_out']),\
                                str(nested_dict['last_tstamp']),str(nested_dict['last_duration']),\
                                    str(nested_dict['count_in']),str(nested_dict['count_out'])]
                    fl = ",".join(lst)
                    n.write(fl+"\n")
            else:
                if port1 <= 1023 or (port1 >= 1024 and port1 <= 32767): #External ip with registered or well known port - flip direction of flow, keep flow
                    nested_dict = fl_dict[key]
                    lst = [str(key[0]),str(key[1]),str(key[2]),str(key[3]),str(key[4]),\
                           str(nested_dict['tstamp']),str(nested_dict['dur']),\
                            str(nested_dict['pkt_in']), str(nested_dict['pkt_out']),\
                                str(nested_dict['bytes_in']),str(nested_dict['bytes_out']),\
                                str(nested_dict['last_tstamp']),str(nested_dict['last_duration']),\
                                    str(nested_dict['count_in']),str(nested_dict['count_out'])]
                    #Flip direction
                    lst[0], lst[1] = lst[1], lst[0] #Flipping IP address
                    lst[2], lst[3] = lst[3], lst[2] #Flipping port numbers
                    lst[7], lst[8] = lst[8], lst[7] #Flipping number of packets
                    lst[9], lst[10] = lst[10], lst[9] #Flippping number of bytes
                    lst[13], lst[14] = lst[14], lst[13] #Flipping number of flows 
                    fl = ",".join(lst)
                    n.write(fl+"\n")
                else: #External IP with ephemeral port communicating with internal IP on well known or registered port - flow dropped
                    continue

    del fl_dict
    return

def flow_prep(netflow_file):
    print("Starting first filter")
    with open(netflow_file, 'r') as file:
        for flow in file:
            is_valid(flow)
            
    flow_merge(netflow_file)

    print("Completed")
    
if __name__ == '__main__':
    netflow_file = sys.argv[1]
    flow_prep(netflow_file)
                
