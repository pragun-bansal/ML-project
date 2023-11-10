import pandas as pd
import numpy as np
import os


csvs = os.listdir('csvs')
csvs = [i for i in csvs if i.endswith('.csv')]

dfs = [pd.read_csv('csvs/' + i) for i in csvs]

for i in range(len(dfs)):
    dfs[i]['device name'] = csvs[i].replace('.csv', '')
    


hybrid = pd.concat(dfs, axis=0)

# replace na with 0
hybrid.fillna(0, inplace=True)
hybrid.replace('', 0, inplace=True)
hybrid.drop(['SRC IP'], axis=1, inplace=True)
# hybrid.sort_values(by=['Arrival Time'], inplace=True)
hybrid.to_csv('hybrid.csv', index=False)
