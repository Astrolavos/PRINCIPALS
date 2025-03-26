### `build_cache.py`
Builds DNS cache

Input: DNS data file name
Output: Pickle file with DNS cache. The DNS cache is a dictionary record format: ip_address: {domain_name, [(timestamp1, timestamp1 + ttl1), (timestamp2, timestamp2 + ttl2), ...]}
The list of tuples contains the valid time intervals for the domain name

### `clean_netflow.py`
Program to clean, merge and orient netflow data

Input: Netflow data file name
Output: Cleaned and merged netflow data csv file


### `flow_stitching.py`
DNS-Flow stitching with one day or two day DNS cache

Input: Cleaned netflow data file name, DNS cache pickle file name 1, DNS cache pickle file name 2 (optional)
Output: Output file last last two column indicating whether flow is stitched, orphan, before, expired or between and the domain name if applicable and time delta if applicable

