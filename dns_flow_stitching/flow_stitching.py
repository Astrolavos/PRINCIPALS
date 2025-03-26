#DNS-Flow stitching with one day or two day DNS cache
#Input: Cleaned netflow data file name, DNS cache pickle file name 1, DNS cache pickle file name 2 (optional)
#Output: Output file last last two column indicating whether flow is stitched, orphan, before, expired or between and the domain name if applicable and time delta if applicable

from multiprocessing import Pool, TimeoutError
import pickle
from datetime import datetime, timedelta
import sys
import bisect

poolsize = 22

cache1  = None
cache2 = None

use_cahce2 = False

def flow_stitch(line):
    tempflow = line.strip().split(',')
    stat = 0
    flag = 0
    temp_tstamp = -1

    if tempflow[1] in cache1:
        rr = cache1[tempflow[1]]
        tempflow.pop() #Removing orphan string
        tempflow.append(rr[0]) #Adding domain name
        stat = 1
        t_lst = rr[1]
        first_tstamp = t_lst[0]
        last_tstamp = t_lst[-1]
        if float(tempflow[5]) < first_tstamp[0]:
            stat = 3
            delta = first_tstamp[0] - float(tempflow[5])
            tempflow.append(delta)
            temp_tstamp = first_tstamp[0]
        elif float(tempflow[5]) > last_tstamp[1]:
            stat = 2
            delta = float(tempflow[5]) - last_tstamp[1]
            tempflow.append(delta)
        else:
            test_tstamp = float(tempflow[5])
            first_values = [tup[0] for tup in t_lst]
            index = bisect.bisect_left(first_values, test_tstamp) #if not expired, check with all the time ranges until a match is found (binary search)
            del first_values
            for i in range(max(0,(index - 10)), len(t_lst)):
                if t_lst[i][0] <= test_tstamp <= t_lst[i][1]:
                    flag = 1
                    break 
            if flag == 0:
                stat = 4
    if use_cahce2:
        if stat == 0 or stat == 3: #If the flow is still orphan or if it is before after search cache1, check with cache2
            flag = 0
            if tempflow[1] in cache2:
                rr = cache2[tempflow[1]]
                if stat == 0:
                    tempflow.pop() #Removing orphan string incase of hit in cache2
                if stat == 3:
                    tempflow.pop() #Removing delta from cache1 stitching
                    tempflow.pop() #Removing domain from cache1 stitching 
                tempflow.append(rr[0]) #Adding domain name
                stat = 1
                t_lst = rr[1]
                first_tstamp = t_lst[0]
                last_tstamp = t_lst[-1]
                if float(tempflow[5]) < first_tstamp[0]:
                    stat = 3
                    delta = first_tstamp[0] - float(tempflow[5])
                    tempflow.append(delta)
                elif float(tempflow[5]) > last_tstamp[1]: #Need to fix this part
                    if float(tempflow[5]) < temp_tstamp:
                        stat = 4
                    else:
                        stat = 2
                        delta = float(tempflow[5]) - last_tstamp[1]
                        tempflow.append(delta)
                else:
                    test_tstamp = float(tempflow[5])
                    first_values = [tup[0] for tup in t_lst]
                    index = bisect.bisect_left(first_values, test_tstamp) #if not expired, check with all the time ranges until a match is found. Updated with binary search.
                    del first_values
                    for i in range(max(0,(index - 10)), len(t_lst)):
                        if t_lst[i][0] <= test_tstamp <= t_lst[i][1]:
                            flag = 1
                            break 
                    if flag == 0:
                        stat = 4
    
    return tempflow, stat

def stitching_main():
    global use_cahce2
    netflow_file = sys.argv[1]
    fname_dns1 = sys.argv[2]
    if len(sys.argv) == 4:
        use_cahce2 = True
        fname_dns2 = sys.argv[3]
        print("Using two DNS cache")
    else:
        print("Using one DNS cache")
    netflow_data = []
    print("Started reading netflow")
    with open(netflow_file) as f:
        for line in f:
            netflow_data.append(line)
    print("Netflow read complete")

    print("Loading cache pickles")
    with open(fname_dns1, 'rb') as handle:
        global cache1
        cache1 = pickle.load(handle)
    if use_cahce2:
        with open(fname_dns2, 'rb') as handle:
            global cache2
            cache2 = pickle.load(handle)    

    output_file = netflow_file.split(".")[0] + "_stitching_results.csv"
    out_file = open(output_file, 'w')

    print("Started flow stitching")
    with Pool(processes=poolsize) as pool:
        for j, k in pool.imap_unordered(flow_stitch, netflow_data):
            if k == 1:
                j.append("stitched")
            elif k == 2:
                j.append("expired")
            elif k == 0:
                j.append("orphan")
            elif k == 3:
                j.append("before")
            elif k == 4:
                j.append("between")
            else:
                print("Error: ", j) 

            flow_str = ','.join(str(item) for item in j) + "\n"
            out_file.write(flow_str)
        pool.close()
        pool.join()

    print("Stitching complete")

if __name__ == '__main__':
    stitching_main()
