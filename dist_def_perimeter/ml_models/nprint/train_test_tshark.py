import nprintml
import numpy as np
import os
import sys
import subprocess
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import roc_auc_score
from concurrent.futures import ProcessPoolExecutor, as_completed

FEATURES_DIR=sys.argv[1]
ignore_prefixes = ['geninfo', 'frame']
def process_file(filename):
    print(f"Doing {filename}")
    label = filename.split('_')[-1].split('-')[0]
    df = pd.read_csv(f"{FEATURES_DIR}/{filename}")
    df['label'] = label

    print(f"Completed {filename} belonging to {label}")
    return df

df_list = []
json_files = [f for f in os.listdir(FEATURES_DIR) if f.endswith('.json')]
print(json_files)
#json_files=['benchmarks/device_fingerprinting/tshark_json/14866_chromecast-OFP-T1-74.json']


for f in json_files:
    df_list.append(process_file(f))

combined_df = pd.concat(df_list, ignore_index=True)
for prefix in ignore_prefixes:
    combined_df = combined_df.loc[:, ~combined_df.columns.str.startswith(prefix)]
combined_df.fillna(-1, inplace=True)
combined_df.set_index('label', inplace=True)

label_list = []
sample_list = []
for label, row in combined_df.iterrows():
    sample_list.append(np.array(row))
    label_list.append(label)

X_train, X_test, y_train, y_test = train_test_split(sample_list, label_list)
clf = RandomForestClassifier(n_estimators=1000, max_depth=None, min_samples_split=2, random_state=0)
clf.fit(X_train, y_train) 
y_pred = clf.predict(X_test)
report = classification_report(y_test, y_pred)
print(report)

