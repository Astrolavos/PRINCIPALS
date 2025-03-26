import os
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import sys

output_directory = None

# Function to convert a single .pcap file to .pdml
def convert_pcap_to_pdml(pcap_file):
    pdml_file = pcap_file.split('/')[-1].replace('.pcap', '.pdml')
    pdml_file = os.path.join(output_directory, pdml_file)
    try:
        # Execute tshark to convert .pcap to .pdml using output redirection
        with open(pdml_file, 'w') as pdml_output:
            subprocess.run(['tshark', '-r', pcap_file, '-T', 'pdml'], stdout=pdml_output, check=True)
        return f"Successfully converted: {pcap_file} to {pdml_file}"
    except subprocess.CalledProcessError as e:
        return f"Failed to convert {pcap_file}: {str(e)}"

# Function to find all .pcap files in a directory
def find_pcap_files(directory):
    pcap_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.pcap'):
                pcap_files.append(os.path.join(root, file))
    return pcap_files

# Main function to convert all pcaps in parallel
def convert_all_pcaps_in_directory(directory):
    pcap_files = find_pcap_files(directory)
    print(f"Found {len(pcap_files)} pcap files to convert.")

    # Use ProcessPoolExecutor for parallel execution on multiple cores
    num_cores = multiprocessing.cpu_count()  # Get the number of available cores
    print(f"Using {num_cores} cores for parallel processing.")

    with ProcessPoolExecutor(max_workers=num_cores) as executor:
        future_to_pcap = {executor.submit(convert_pcap_to_pdml, pcap): pcap for pcap in pcap_files}

        # Process as each conversion completes
        for future in as_completed(future_to_pcap):
            pcap = future_to_pcap[future]
            try:
                result = future.result()
                print(result)
            except Exception as e:
                print(f"Error processing {pcap}: {str(e)}")

if __name__ == "__main__":
    pcap_directory = sys.argv[1]
    output_directory = sys.argv[2]
    os.makedirs(output_directory, exist_ok=True) 
    convert_all_pcaps_in_directory(pcap_directory)


