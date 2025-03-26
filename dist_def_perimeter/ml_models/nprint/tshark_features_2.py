import os
import xml.etree.ElementTree as ET
import sys
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
import pandas as pd

def is_hex(s):
    """ Check if the string represents a hexadecimal value. """
    try:
        int(s, 16)  # Try converting string to an int using base 16
        return True
    except ValueError:
        return False

def process_field(proto_name, field, parent_feature_name, valid_set):
    """ Helper function to process fields with local sets in parallel execution. """
    field_name = field.get('name')
    field_value = field.get('show')

    # Create the full feature name by appending to the parent feature name
    if parent_feature_name:
        full_feature_name = f"{parent_feature_name}.{field_name}"
    else:
        full_feature_name = f"{proto_name}.{field_name}"

    # Check if the value is hexadecimal and try to convert
    if field_value is not None:
        try:
            packet_info_value = int(field_value)
            valid_set[full_feature_name] = packet_info_value
        except ValueError:
            if is_hex(field_value):
                packet_info_value = int(field_value, 16)  # Convert hex to int
                valid_set[full_feature_name] = packet_info_value

    # Process nested fields
    for nested_field in field.findall('field'):
        process_field(proto_name, nested_field, full_feature_name, valid_set)

def parse_pdml_to_json(pdml_file):
    """ Parse the PDML file and extract packet information. """
    # Initialize dictionaries to hold field-value pairs

    # Parse the PDML file
    tree = ET.parse(pdml_file)
    root = tree.getroot()
    res_list = []

    # Iterate through each packet in the PDML
    for packet in root.findall('.//packet'):
        valid_features = {}
        # For each protocol inside the packet, excluding certain protocols
        for proto in packet.findall('proto'):
            proto_name = proto.get('name')


            # For each field in the protocol
            for field in proto.findall('field'):
                process_field(proto_name, field, None, valid_features)
        res_list.append(valid_features) 

    return res_list

def save_to_json(data, output_file):
    """ Save the given data to a JSON file. """
    df = pd.DataFrame(data)
    with open(output_file, 'w') as json_file:
        df.to_csv(output_file, index=False)

# Function to process each PDML file and save JSON results
def process_pdml_file(pdml_file, output_dir):
    res_list = parse_pdml_to_json(pdml_file)
    # Create the output JSON file paths
    base_filename = os.path.basename(pdml_file).replace('.pdml', '')
    valid_output_file = os.path.join(output_dir, f"{base_filename}.json")

    # Save valid and invalid features to separate JSON files
    save_to_json(res_list, valid_output_file)

    return pdml_file, valid_output_file

# Main function to process PDML files concurrently
def main():
    pdml_directory = sys.argv[1]  # Path to the directory with PDML files
    output_directory = sys.argv[2]  # Path to the directory to save JSON files
    pdml_files = [os.path.join(pdml_directory, f) for f in os.listdir(pdml_directory) if f.endswith(".pdml")]

    # Ensure output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Use ProcessPoolExecutor to run tasks in parallel
    with ProcessPoolExecutor() as executor:
        futures = {
            executor.submit(process_pdml_file, pdml_file, output_directory): pdml_file for pdml_file in pdml_files
        }

        # Collect results from all processes
        for future in as_completed(futures):
            pdml_file = futures[future]
            try:
                pdml_file, valid_output = future.result()
                print(f"Processed {pdml_file}, saved valid features to {valid_output}")
            except Exception as exc:
                print(f"Error processing {pdml_file}: {exc}")

if __name__ == "__main__":
    main()

