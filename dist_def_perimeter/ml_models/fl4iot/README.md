## Datasets
For data we used our lab's IoT PCAPS from https://yourthings.info/data/


## Code
`tshark_features_multicore.ipynb`: is used to extract tshark features from PCAPs

`extract_features.ipynb`: is used to download some external datasets

`models.py`: is the autoencoder model that we use for our experiments

`autoencoder_anomaly.ipynb`: uses autoencoder for unsupervised learning

`kmeans_anomaly.ipynb`: uses kmeans (potentially with PCA) for unsupervised learning/anomaly detection
