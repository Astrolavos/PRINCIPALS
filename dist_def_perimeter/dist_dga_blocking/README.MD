# Installation
Run `pip -r requirements.txt` and copy all files into all environments that plan to run any of these scripts.

# Scripts
## central_db.py
This is a flask server that places "POST"ed data to a sql database, and returns the data when a GET request is sent.
The endpoint is `localhost:5000/dga`, though you can change this through the flask settings.
Every time this script is run, a database file is created (if one exists, it is deleted and then recreated.)
This file contains all the potential DGA domains

## dga_detector.py
This file accepts one command line input for the interface to listen for DNS queries to potential DGA domains.
If it has a match, it pushes data to the database created by the `central_db.py` script via the `/dga` endpoint

## dga_blocker.py
This file accepts one command line input for the interface to block DNS responses to seen DGA domains.
It pulls the list of detecting DGA responses from the database created by the `central_db.py` script via the `/dga` endpoint.
If this script identifies a DGA domain in a DNS response, it blocks all IPs in the response's rdata by creating `iptables` rules.
This only works on ipv4 addresses, and will ignore any ipv6.
