import sys
import pandas as pd

filename =  sys.argv[1]
df = pd.read_csv(filename)
x = df.loc[:, (df == 0).all()]
print(x.columns)
