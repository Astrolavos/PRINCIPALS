#!/bin/bash

ip_list="192.168.0.12 192.168.0.13 192.168.0.15 192.168.0.18 192.168.0.23 192.168.0.33 192.168.0.35 192.168.0.38 192.168.0.39 192.168.0.47 192.168.0.48 192.168.0.52 192.168.0.8"
for ip in $ip_list;
do
	for day in 10 11 12;
	do
		mkdir -p parsed_data/$day
		input_file=/mnt/iotlab_data/$day/${ip}.pcap
		output_file=parsed_data/$day/${ip}.csv
		echo $input_file $output_file
		python3 v_code_realtime.py --filename $input_file --target $ip --count -1 --outfile $output_file
	done
done
