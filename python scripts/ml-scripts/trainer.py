import matplotlib.pyplot as plt
from sklearn import preprocessing
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import warnings
import math
warnings.filterwarnings("ignore")

from sklearn import metrics
from sklearn.model_selection import train_test_split
import tensorflow as tf


df=pd.read_csv("hybrid.csv")
df.fillna(0, inplace=True)
print(df.shape)
print(df.head())

x = df.iloc[:,0:30]
min_max_scaler = preprocessing.MinMaxScaler()

y= df['device name'].astype('category')

y=y.cat.codes
y=y.values
y=np.array(y)


from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size=0.35,random_state=1)

from sklearn import preprocessing
min_max_scaler = preprocessing.MinMaxScaler()

x_train = min_max_scaler.fit_transform(x_train)
x_test = min_max_scaler.transform(x_test)

print(x_train.shape,x_test.shape)
print(y_train )
print("x_train shape : ", x_train.shape)
print("y_train shape : ", y_train.shape)


from keras.models import Sequential
from keras.layers import Dense, Conv2D, Dropout, Flatten, MaxPooling2D

# print(x_train.head())

model = Sequential()
model.add(Dense(30,activation='relu',input_dim=30))
model.add(Dense(15,activation='relu'))
model.add(Dense(12,activation='relu'))
model.add(Dense(10,activation='softmax'))

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy',  metrics=['accuracy'])
model.fit(x=x_train,y=y_train, epochs=20)
model.evaluate(x_test, y_test)
