#Build DNS cache
#Multiprocessing with 16 parallel processes using the first charecter of the hash of the IP address to split the data
#Input: DNS data file name
#Output: Pickle file with DNS cache
#DNS cache is a dictionary record format: ip_address: {domain_name, [(timestamp1, timestamp1 + ttl1), (timestamp2, timestamp2 + ttl2), ...]}
#The list of tuples contains the valid time intervals for the domain name

import hashlib
import sys
import multiprocessing
import pickle
from datetime import datetime
import os
import copy
import orjson
import resource
import time
import bisect


hex_dict = {hex(i)[2:]: [] for i in range(16)}
mem_size = 1000000000 * 480

def cache_build(lst, temp_cache):
    t_cache = {}
    count = 0
    print("Process started: ", os.getpid(), " List length: ", len(lst), flush=True, file=sys.stdout)
    for line in lst:
        start_time = time.time()
        count += 1
        if count % 10000000 == 0:
            print(os.getpid(), " completed: ", count, " lines", flush=True, file=sys.stdout)
        data = line.strip().split(',')
        rdata = data[2]
        rname = data[3]
        tstamp = int(data[0])
        ttl = int(data[0]) + int(data[1])
        temp_tuple = (tstamp, ttl)
        if rdata in t_cache:           
            temp = t_cache[rdata]
            t = temp[1][-1]
            if t == temp_tuple:
                continue
            elif tstamp <= t[1] and tstamp >= t[0]:  
                temp[1].pop()
            elif tstamp > t[0] and ttl < t[1]: 
                continue
            elif ttl >= t[0] and ttl <= t[1]: 
                temp_tuple = (tstamp, t[1])
                temp[1].pop()
            index = bisect.bisect_left(temp[1], temp_tuple)
            temp[1].insert(index, temp_tuple) 
            t_cache[rdata] = temp
        else:                           
            t_list = []
            t_list.append(temp_tuple)
            rr = [rname, t_list]
            t_cache[rdata] = rr
    temp_cache.update(t_cache)
    print("Process ended: ", os.getpid())
 

def data_hash(dns_file):
    print("Started hashing")
    with open(dns_file, 'r') as file:
        for l in file:
            data = orjson.loads(str(l))
            if data['response'] is True and 'rtype' in data:
                if data['rtype'] is not None and (data['rtype'] == 1):
                    timestamp = data['timestamp']
                    ttl = data['ttl']
                    ip = data['rdata']
                    domain = data['rname']
                    # dest = data['ip_dst']
                    d = [str(timestamp),str(ttl),ip,domain]
                    line = ','.join(d) + "\n"
                    hsh = hashlib.md5(ip.encode())
                    strng = hsh.hexdigest()
                    hex_dict[strng[0]].append(line)

def limit_memory(maxsize):
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (maxsize, hard))

if __name__ == '__main__':
    dns_file = sys.argv[1]

    data_hash(dns_file)
    
    print("Started multiprocess")
    manager = multiprocessing.Manager()
    cache = manager.dict()
    jobs = []
    for key in hex_dict:
        p = multiprocessing.Process(target=cache_build, args=(hex_dict[key], cache))
        jobs.append(p)
        p.start()
    for proc in jobs:
        proc.join()
    print("Completed multiprocess")
    print("Writing cache to file")
    print(cache)
    cache_copy = copy.deepcopy(cache)
    fname1 = dns_file+ "_cache.pickle"
    with open(fname1, 'wb') as handle:
        pickle.dump(cache_copy, handle, protocol=pickle.HIGHEST_PROTOCOL)
    print("Completed")


