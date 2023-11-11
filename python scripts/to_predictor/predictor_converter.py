# import numpy as np
import pandas as pd

# Load data
df = pd.read_csv('predictor.csv')
df.drop(labels='SRC IP', axis=1, inplace=True)
# insert 
df['Label'] = 'Watch_Sensor'
df.to_csv('watch_sensor_final_test.csv', index=False)

