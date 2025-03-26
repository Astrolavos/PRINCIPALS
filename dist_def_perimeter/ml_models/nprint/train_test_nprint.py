import nprintml
import numpy as np
import os
import subprocess
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import roc_auc_score
from concurrent.futures import ProcessPoolExecutor, as_completed

PCAP_DIR="output_dir"
FEATURES_DIR="features_dir"
os.makedirs(FEATURES_DIR, exist_ok=True)


def process_file(pcap_name, label_raw):
    label = label_raw.split('-')[0]
    npt_name = pcap_name.replace('pcap', 'npt')
    
    # Read the nprint file
    nprint = pd.read_csv(f'{FEATURES_DIR}/{npt_name}', index_col=0)
    
    # Collect samples and labels
    sample_list = []
    label_list = []
    for _, row in nprint.iterrows():
        sample_list.append(np.array(row))
        label_list.append(label)
    
    return sample_list, label_list

if False:
    data = np.genfromtxt(f'{PCAP_DIR}/metadata.csv', delimiter=',', dtype=None, encoding='utf-8', names=True)
    for pcap_name, label_raw in data:
        label = label_raw.split('-')[0]
        npt_name = pcap_name.replace('pcap', 'npt')
        cmd = f'nprint -P {PCAP_DIR}/{pcap_name} -4 -W {FEATURES_DIR}/{npt_name}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)


samples = []
labels = []

if True:
    data = np.genfromtxt(f'{PCAP_DIR}/metadata.csv', delimiter=',', dtype=None, encoding='utf-8', names=True)
    with ProcessPoolExecutor(max_workers=100) as executor:
    	# Submit all tasks to the executor
    	futures = [executor.submit(process_file, pcap_name, label_raw) for pcap_name, label_raw in data]

    # As each task completes, append the results
    for future in as_completed(futures):
        sample_list, label_list = future.result()
        samples.extend(sample_list)
        labels.extend(label_list)


X_train, X_test, y_train, y_test = train_test_split(samples, labels)
clf = RandomForestClassifier(n_estimators=1000, max_depth=None, min_samples_split=2, random_state=0)
clf.fit(X_train, y_train) 
y_pred = clf.predict(X_test)
report = classification_report(y_test, y_pred)
print(report)

